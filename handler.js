const crypto = require('crypto');
const fs = require('fs');
const { Octokit } = require("@octokit/rest");
const { retry } = require("@octokit/plugin-retry");
const permissionsPolicy = require('./policies/permissions.json');
const visibilityPolicy = require('./policies/visibility.json');
const JiraApi = require('jira-client');

const MyOctokit = Octokit.plugin(
  retry
);

function signRequestBody(key, body) {
  return `sha1=${crypto.createHmac('sha1', key).update(body, 'utf-8').digest('hex')}`;
}

async function asyncForEach(array, callback) {
  for (let index = 0; index < array.length; index++) {
    await callback(array[index], index, array);
  }
}

module.exports.githubWebhookListener = (event, context, callback) => {
  var errMsg; // eslint-disable-line
  const token = process.env.GITHUB_WEBHOOK_SECRET;
  const headers = event.headers;
  const sig = headers['X-Hub-Signature'];
  const githubEvent = headers['X-GitHub-Event'];
  const id = headers['X-GitHub-Delivery'];
  const calculatedSig = signRequestBody(token, event.body);

  if (typeof token !== 'string') {
    errMsg = 'Must provide a \'GITHUB_WEBHOOK_SECRET\' env variable';
    return callback(null, {
      statusCode: 401,
      headers: { 'Content-Type': 'text/plain' },
      body: errMsg,
    });
  }

  if (!sig) {
    errMsg = 'No X-Hub-Signature found on request';
    return callback(null, {
      statusCode: 401,
      headers: { 'Content-Type': 'text/plain' },
      body: errMsg,
    });
  }

  if (!githubEvent) {
    errMsg = 'No X-Github-Event found on request';
    return callback(null, {
      statusCode: 422,
      headers: { 'Content-Type': 'text/plain' },
      body: errMsg,
    });
  }

  if (!id) {
    errMsg = 'No X-Github-Delivery found on request';
    return callback(null, {
      statusCode: 401,
      headers: { 'Content-Type': 'text/plain' },
      body: errMsg,
    });
  }

  if (sig !== calculatedSig) {
    errMsg = 'X-Hub-Signature incorrect. Github webhook token doesn\'t match';
    return callback(null, {
      statusCode: 401,
      headers: { 'Content-Type': 'text/plain' },
      body: errMsg,
    });
  }

  /* eslint-disable */
  console.log('---------------------------------');
  console.log(`Github-Event: "${githubEvent}"`);
  console.log('---------------------------------');
  console.log('Webhook Headers', JSON.stringify(headers));
  console.log('Payload', event.body);
  /* eslint-enable */

  // Do custom stuff here with github event data
  // For more on events see https://developer.github.com/v3/activity/events/types/

  // check to see if this repo is excluded from the permission policy, and, if so, skip evaluation
  const body = JSON.parse(event.body);
  const repository = body.repository;
  const action = body.action;
  const whitelisted_actions = [
    "added_to_repository",
    undefined
  ]

  const octokit = new MyOctokit({
    auth: process.env.GITHUB_API_TOKEN,
    userAgent: 'github-org-settings',
    timeZone: 'America/Chicago',
    baseUrl: 'https://api.github.com',
    log: {
      debug: () => {},
      info: () => {},
      warn: console.warn,
      error: console.error
    },  
    request: {
      agent: undefined,
      fetch: undefined,
      timeout: 0
    }
  });

  let ghChanges = [];
  let repoTeams = [];

  async function checkPolicies() {
    if (!permissionsPolicy.exceptions.repositories.includes(repository.name)) {
      await getTeamList();
      await asyncForEach(permissionsPolicy.default.teams, validateTeamPermissions)
    }
    await validateVisibility();
    await logAction();
  }

  if (!whitelisted_actions.includes(action)) {
    checkPolicies();
  }

  async function getTeamList() {
    let result = await octokit.repos.listTeams({
      owner: 'process.env.GITHUB_ORG',
      repo: repository.name
    });
    repoTeams = result.data;
  }

  async function validateTeamPermissions(teamPolicy) {
    let currentPermission = repoTeams.find(o => o.name == teamPolicy.name);
    if(currentPermission === undefined || currentPermission.permission != teamPolicy.permission) {
      let result = await octokit.teams.addOrUpdateRepoInOrg({
        org: 'process.env.GITHUB_ORG',
        team_slug: teamPolicy.slug,
        owner: 'process.env.GITHUB_ORG',
        repo: repository.name,
        permission: teamPolicy.permission
      });
      ghChanges.push(teamPolicy.name + " team added to " + repository.name + " with " + teamPolicy.permission + " permission.");
      console.log("ghChanges[] = " + JSON.stringify(ghChanges));
    }
  };

  async function validateVisibility() {
    let exceptedRepo = visibilityPolicy.exceptions.repositories.includes(repository.name);
    let defaultPrivate = (visibilityPolicy.default == "private")
    let desiredPrivate = ((defaultPrivate && !exceptedRepo) || (!defaultPrivate && exceptedRepo));
    if (repository.private != desiredPrivate) {
      let result = await octokit.repos.update({
        owner: 'process.env.GITHUB_ORG',
        repo: repository.name,
        private: desiredPrivate
      });
      let visibility = (desiredPrivate) ? "private" : "public";
      ghChanges.push(repository.name + " visibility set to " + visibility);
      console.log("ghChanges[] = " + JSON.stringify(ghChanges));
    }
  }

  async function logAction() {
    console.log("ghChanges length = " + ghChanges.length);
    if(ghChanges.length > 0) {
      const jira = new JiraApi({
        protocol: 'https',
        host: process.env.JIRA_FQDN,
        username: process.env.ATLASSIAN_API_USER,
        password: process.env.ATLASSIAN_API_TOKEN,
        apiVersion: '2',
        strictSSL: true
      });

      let issueDescription = "Changes made to the repository:\n";

      ghChanges.forEach(function(change) {
        issueDescription += "* " + change + "\n";
      });

      const issue = await jira.addNewIssue({
        "fields": {
          "project":
          {
              "key": process.env.JIRA_PROJECT_KEY
          },
          "summary": "GitHub Repository \"" + repository.name + "\" Configuration Updated",
          "description": issueDescription,
          "issuetype": {
              "name": process.env.JIRA_ISSUETYPE_NAME
          }
        }
      });
      console.log(`Created Jira Issue: ${issue.key} (see ${issue.self})`);
    }
  }

  const response = {
    statusCode: 200,
    body: JSON.stringify({
      input: event,
    }),
  };

  return callback(null, response);
};