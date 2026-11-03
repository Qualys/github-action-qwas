# Qualys WAS GitHub Action


## Description

The workflow of GitHub Actions has four main steps:
1. Prerequisites 
2. Configure GitHub Environment Parameters 
3. Configure GitHub Action 
4. Download Scan Results

This README document explains how to use the Qualys WAS GitHub Action and gives some samples for your reference.

## How to use the Qualys WAS GitHub Action

1. Visit [GitHub configuring a workflow](https://help.github.com/en/actions/configuring-and-managing-workflows/configuring-a-workflow) to enable GitHub Action in your repository.
   [configuring-a-workflow](https://help.github.com/en/actions/configuring-and-managing-workflows/configuring-a-workflow)
2. Subscribe to Qualys WAS module and obtain Qualys credentials.
3. Choose an authentication type (`AUTH_TYPE`): `BASIC`, `OAUTH`, or `IDP`.
   - **BASIC**: Use Qualys username and password.
   - **OAUTH**: Use Qualys API client ID and client secret (token obtained from Qualys gateway `/auth/oidc` endpoint).
   - **IDP**: Use an external Identity Provider (IDP) with client credentials grant. Requires `IDP_TOKEN_URL`, and optionally `IDP_SCOPE` and `IDP_AUDIENCE`.
4. Create GitHub Secrets and variables. Refer to GitHub Action Parameter section below to learn about the parameters.
   Refer to [Encrypted secrets](https://docs.github.com/en/actions/reference/encrypted-secrets) for more details on how to set up secrets.
5. Configure your workflow. In the actions steps of run.yaml file use `Qualys/github-action-qwas@<release-tag>` (or a full commit SHA). See [Releases](https://github.com/Qualys/github-action-qwas/releases) for the latest version.
6. You can use the Input Parameters to customize GitHub Action as per your requirements.

Note: The `actions/checkout` step is required to run before the scan action, otherwise the action does not have access to the Web apps to be scanned.

## Usage Examples

Qualys WAS GitHub Actions can be used to trigger repository scan in different events. Following are some sample scan events for your reference:

### Scan Web App in your repository on push event

Refer to the below sample to scan web applications in your repository on push event.
```yaml
name: Qualys WAS Scan 
on:
  push:
    branches:
      - main
jobs:
    Qualys_was_scan:
        runs-on: ubuntu-latest
        name: Qualys WAS Scan
        steps:
          - name: Checkout
            uses: actions/checkout@v3 
            with:
                fetch-depth: 0
    
          - name: Qualys WAS scan action step
            uses: Qualys/github-action-qwas@<release-tag>
            id: was
            with:
              API_SERVER: ${{ vars.API_SERVER }}
              AUTH_TYPE: ${{ vars.AUTH_TYPE }}
              QUALYS_USERNAME: ${{ vars.QUALYS_USERNAME }}
              QUALYS_PASSWORD: ${{ secrets.QUALYS_PASSWORD }}
              CLIENT_ID: ${{ vars.CLIENT_ID }}
              CLIENT_SECRET: ${{ secrets.CLIENT_SECRET }}
              IDP_TOKEN_URL: ${{ vars.IDP_TOKEN_URL }}
              IDP_SCOPE: ${{ vars.IDP_SCOPE }}
              IDP_AUDIENCE: ${{ vars.IDP_AUDIENCE }}
              WEBAPP_ID: ${{ vars.WEBAPP_ID }}
              SCAN_NAME: ${{ vars.SCAN_NAME }}
              SCAN_TYPE: ${{ vars.SCAN_TYPE }}
              AUTH_RECORD: ${{ vars.AUTH_RECORD }}
              AUTH_RECORD_ID: ${{ vars.AUTH_RECORD_ID }}
              OPTION_PROFILE: ${{ vars.OPTION_PROFILE }}
              OPTION_PROFILE_ID: ${{ vars.OPTION_PROFILE_ID }}
              CANCEL_OPTION: ${{ vars.CANCEL_OPTION }}
              CANCEL_HOURS: ${{ vars.CANCEL_HOURS }}
              SEVERITY_CHECK: ${{ vars.SEVERITY_CHECK }}
              SEVERITY_LEVEL: ${{ vars.SEVERITY_LEVEL }}
              EXCLUDE: ${{ vars.EXCLUDE }}
              FAIL_ON_SCAN_ERROR: ${{ vars.FAIL_ON_SCAN_ERROR }}
              WAIT_FOR_RESULT: ${{ vars.WAIT_FOR_RESULT }}
              INTERVAL: ${{ vars.INTERVAL }}
              TIMEOUT: ${{ vars.TIMEOUT }}
              FILE_TYPE: ${{ vars.FILE_TYPE }}
              ARTIFACT_RETENTION_DAYS: ${{ vars.ARTIFACT_RETENTION_DAYS }}
              SEND_MAIL: ${{ vars.SEND_MAIL }}
```

To download the scan result in your repository, checkout the repository using below code. 
If the repository is private, then add a PAT (personal access token) in the checkout step.
```yaml
          - name: checkout code
            uses: actions/checkout@v3
            with:
             repository: GITHUB_USERNAME/REPOSITORY_NAME
             ref: BRANCH_NAME
             path: ./
             PAT: ${{ secrets.ACCESS_TOKEN }}

          - name: Download Result
            uses: actions/download-artifact@v4
            with:
             name: Qualys_WAS_Scan_Result
             path: PATH_TO_TARGET_DIRECTORY 
```
### Scan Web App in your repository on pull request event
Refer to the below sample to scan web applications in your repository on pull request event.
```yaml
name: Qualys WAS Scan 
on:
  pull_request:
    branches:
      - main 
jobs:
  Qualys_was_scan:
    runs-on: ubuntu-latest
    name: Qualys WAS Scan
    steps:
      - name: Checkout
        uses: actions/checkout@v3
        with:
          fetch-depth: 0
      
      - name: Qualys WAS scan action step
        uses: Qualys/github-action-qwas@<release-tag>
        id: was
        with:
          API_SERVER: ${{ vars.API_SERVER }}
          AUTH_TYPE: ${{ vars.AUTH_TYPE }}
          QUALYS_USERNAME: ${{ vars.QUALYS_USERNAME }}
          QUALYS_PASSWORD: ${{ secrets.QUALYS_PASSWORD }}
          CLIENT_ID: ${{ vars.CLIENT_ID }}
          CLIENT_SECRET: ${{ secrets.CLIENT_SECRET }}
          IDP_TOKEN_URL: ${{ vars.IDP_TOKEN_URL }}
          IDP_SCOPE: ${{ vars.IDP_SCOPE }}
          IDP_AUDIENCE: ${{ vars.IDP_AUDIENCE }}
          WEBAPP_ID: ${{ vars.WEBAPP_ID }}
          SCAN_NAME: ${{ vars.SCAN_NAME }}
          SCAN_TYPE: ${{ vars.SCAN_TYPE }}
          AUTH_RECORD: ${{ vars.AUTH_RECORD }}
          AUTH_RECORD_ID: ${{ vars.AUTH_RECORD_ID }}
          OPTION_PROFILE: ${{ vars.OPTION_PROFILE }}
          OPTION_PROFILE_ID: ${{ vars.OPTION_PROFILE_ID }}
          CANCEL_OPTION: ${{ vars.CANCEL_OPTION }}
          CANCEL_HOURS: ${{ vars.CANCEL_HOURS }}
          SEVERITY_CHECK: ${{ vars.SEVERITY_CHECK }}
          SEVERITY_LEVEL: ${{ vars.SEVERITY_LEVEL }}
          EXCLUDE: ${{ vars.EXCLUDE }}
          FAIL_ON_SCAN_ERROR: ${{ vars.FAIL_ON_SCAN_ERROR }}
          WAIT_FOR_RESULT: ${{ vars.WAIT_FOR_RESULT }}
          INTERVAL: ${{ vars.INTERVAL }}
          TIMEOUT: ${{ vars.TIMEOUT }}
          FILE_TYPE: ${{ vars.FILE_TYPE }}
          ARTIFACT_RETENTION_DAYS: ${{ vars.ARTIFACT_RETENTION_DAYS }}
          SEND_MAIL: ${{ vars.SEND_MAIL }}
```
To download the scan result in your repository, checkout the repository using the following code. 
If the repository is private, then add a PAT (personal access token) in the checkout step.
```yaml
      - name: checkout code
        uses: actions/checkout@v3
        with:
           repository: GITHUB_USERNAME/REPOSITORY_NAME
           ref: BRANCH_NAME
           path: ./
           PAT: ${{ secrets.ACCESS_TOKEN }}

      - name: Download Result
        uses: actions/download-artifact@v4
        with:
           name: Qualys_WAS_Scan_Result
           path: PATH_TO_TARGET_DIRECTORY
```

### Scan Web App in your repository on manual trigger
Refer to the below sample to scan web applications in your repository on manual trigger event.
```yaml
name: Qualys WAS Scan 
on: workflow_dispatch
jobs:
  Qualys_was_scan:
    runs-on: ubuntu-latest
    name: Qualys WAS Scan
    steps:
      - name: Checkout
        uses: actions/checkout@v3
        with:
          fetch-depth: 0
      
      - name: Qualys WAS scan action step
        uses: Qualys/github-action-qwas@<release-tag>
        id: was
        with:
          API_SERVER: ${{ vars.API_SERVER }}
          AUTH_TYPE: ${{ vars.AUTH_TYPE }}
          QUALYS_USERNAME: ${{ vars.QUALYS_USERNAME }}
          QUALYS_PASSWORD: ${{ secrets.QUALYS_PASSWORD }}
          CLIENT_ID: ${{ vars.CLIENT_ID }}
          CLIENT_SECRET: ${{ secrets.CLIENT_SECRET }}
          IDP_TOKEN_URL: ${{ vars.IDP_TOKEN_URL }}
          IDP_SCOPE: ${{ vars.IDP_SCOPE }}
          IDP_AUDIENCE: ${{ vars.IDP_AUDIENCE }}
          WEBAPP_ID: ${{ vars.WEBAPP_ID }}
          SCAN_NAME: ${{ vars.SCAN_NAME }}
          SCAN_TYPE: ${{ vars.SCAN_TYPE }}
          AUTH_RECORD: ${{ vars.AUTH_RECORD }}
          AUTH_RECORD_ID: ${{ vars.AUTH_RECORD_ID }}
          OPTION_PROFILE: ${{ vars.OPTION_PROFILE }}
          OPTION_PROFILE_ID: ${{ vars.OPTION_PROFILE_ID }}
          CANCEL_OPTION: ${{ vars.CANCEL_OPTION }}
          CANCEL_HOURS: ${{ vars.CANCEL_HOURS }}
          SEVERITY_CHECK: ${{ vars.SEVERITY_CHECK }}
          SEVERITY_LEVEL: ${{ vars.SEVERITY_LEVEL }}
          EXCLUDE: ${{ vars.EXCLUDE }}
          FAIL_ON_SCAN_ERROR: ${{ vars.FAIL_ON_SCAN_ERROR }}
          WAIT_FOR_RESULT: ${{ vars.WAIT_FOR_RESULT }}
          INTERVAL: ${{ vars.INTERVAL }}
          TIMEOUT: ${{ vars.TIMEOUT }}
          FILE_TYPE: ${{ vars.FILE_TYPE }}
          ARTIFACT_RETENTION_DAYS: ${{ vars.ARTIFACT_RETENTION_DAYS }}
          SEND_MAIL: ${{ vars.SEND_MAIL }}
```
To download the scan result in your repository, checkout the repository using the following code. 
If the repository is private, then add a PAT (personal access token) in the checkout step.
```yaml
      - name: checkout code
        uses: actions/checkout@v3
        with:
           repository: GITHUB_USERNAME/REPOSITORY_NAME
           ref: BRANCH_NAME
           path: ./
           PAT: ${{ secrets.ACCESS_TOKEN }}

      - name: Download Result
        uses: actions/download-artifact@v4
        with:
           name: Qualys_WAS_Scan_Result
           path: PATH_TO_TARGET_DIRECTORY
```

### Scan Web Application on Scheduled Trigger
Refer to the below sample to scan web applications in your repository on scheduled trigger events.
```yaml
name: Qualys WAS Scan 
on: 
    schedule:
        - cron: '30 5 * * 1,3'
jobs:
  Qualys_was_scan:
    runs-on: ubuntu-latest
    name: Qualys WAS Scan
    steps:
      - name: Checkout
        uses: actions/checkout@v3
        with:
          fetch-depth: 0
      
      - name: Qualys WAS scan action step
        uses: Qualys/github-action-qwas@<release-tag>
        id: was
        with:
          API_SERVER: ${{ vars.API_SERVER }}
          AUTH_TYPE: ${{ vars.AUTH_TYPE }}
          QUALYS_USERNAME: ${{ vars.QUALYS_USERNAME }}
          QUALYS_PASSWORD: ${{ secrets.QUALYS_PASSWORD }}
          CLIENT_ID: ${{ vars.CLIENT_ID }}
          CLIENT_SECRET: ${{ secrets.CLIENT_SECRET }}
          IDP_TOKEN_URL: ${{ vars.IDP_TOKEN_URL }}
          IDP_SCOPE: ${{ vars.IDP_SCOPE }}
          IDP_AUDIENCE: ${{ vars.IDP_AUDIENCE }}
          WEBAPP_ID: ${{ vars.WEBAPP_ID }}
          SCAN_NAME: ${{ vars.SCAN_NAME }}
          SCAN_TYPE: ${{ vars.SCAN_TYPE }}
          AUTH_RECORD: ${{ vars.AUTH_RECORD }}
          AUTH_RECORD_ID: ${{ vars.AUTH_RECORD_ID }}
          OPTION_PROFILE: ${{ vars.OPTION_PROFILE }}
          OPTION_PROFILE_ID: ${{ vars.OPTION_PROFILE_ID }}
          CANCEL_OPTION: ${{ vars.CANCEL_OPTION }}
          CANCEL_HOURS: ${{ vars.CANCEL_HOURS }}
          SEVERITY_CHECK: ${{ vars.SEVERITY_CHECK }}
          SEVERITY_LEVEL: ${{ vars.SEVERITY_LEVEL }}
          EXCLUDE: ${{ vars.EXCLUDE }}
          FAIL_ON_SCAN_ERROR: ${{ vars.FAIL_ON_SCAN_ERROR }}
          WAIT_FOR_RESULT: ${{ vars.WAIT_FOR_RESULT }}
          INTERVAL: ${{ vars.INTERVAL }}
          TIMEOUT: ${{ vars.TIMEOUT }}
          FILE_TYPE: ${{ vars.FILE_TYPE }}
          ARTIFACT_RETENTION_DAYS: ${{ vars.ARTIFACT_RETENTION_DAYS }}
          SEND_MAIL: ${{ vars.SEND_MAIL }}
```
To download the scan result in your repository, checkout the repository using the following code.
If the repository is private, then add a PAT (personal access token) in the checkout step.
```yaml
      - name: checkout code
        uses: actions/checkout@v3
        with:
           repository: GITHUB_USERNAME/REPOSITORY_NAME
           ref: BRANCH_NAME
           path: ./
           PAT: ${{ secrets.ACCESS_TOKEN }}

      - name: Download Result
        uses: actions/download-artifact@v4
        with:
           name: Qualys_WAS_Scan_Result
           path: PATH_TO_TARGET_DIRECTORY
```

## Prerequisites for Qualys WAS GitHub Action
1. Valid Qualys Credentials and subscription to Qualys WAS and Qualys API.
2. Use the `actions/checkout@v3` step with` fetch-depth: 0` before calling Qualys WAS GitHub action.
3. While working on the self-hosted runners, ensure that your machine has stable internet connection.
4. Set the `API_SERVER` parameter to your Qualys API server URL (e.g. https://qualysapi.qualys.com). [Click here](https://www.qualys.com/platform-identification/) to identify the API server URL for your platform.
5. Set the `AUTH_TYPE` parameter to one of `BASIC`, `OAUTH`, or `IDP`.
6. Add `QUALYS_PASSWORD` and `CLIENT_SECRET` in `secrets` and remaining parameters to the `repository variables` of Qualys WAS GitHub action.
7. For `IDP` auth, ensure `IDP_TOKEN_URL` is configured. `IDP_SCOPE` and `IDP_AUDIENCE` are optional.
8. For `OAUTH` or `IDP` auth, ensure `CLIENT_ID` and `CLIENT_SECRET` are configured.

## GitHub action Parameters

| Parameter          | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Mandatory/ Optional | Default Value | Parameter Type |
|--------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------|---------------|----------------|
| API_SERVER         | Qualys API Server URL (e.g. https://qualysapi.qualys.com). Must use `https://`; the action rejects plain `http://` URLs. [Click here](https://www.qualys.com/platform-identification/) to identify the API server URL for your platform. The Qualys gateway URL (used for OAUTH token generation) and portal URL are derived automatically by the action from this value.                                                                                                                                                                                                                                                     | Mandatory           | ""            | Variable       |
| AUTH_TYPE          | Authentication type. Use one of the following: BASIC: Use Qualys username and password. OAUTH: Use Qualys API client credentials (CLIENT_ID and CLIENT_SECRET). IDP: Use an external Identity Provider with client credentials grant.                                                                                                                                                                                                                                                                                                          | Mandatory           | ""            | Variable       |
| QUALYS_USERNAME    | Qualys Username. Required when AUTH_TYPE is BASIC.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Optional            | ""            | Variable       |
| QUALYS_PASSWORD    | Qualys Password. Required when AUTH_TYPE is BASIC.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Optional            | ""            | Secret         |
| CLIENT_ID          | Qualys API Client ID. Required when AUTH_TYPE is OAUTH or IDP.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Optional            | ""            | Variable       |
| CLIENT_SECRET      | Qualys API Client Secret. Required when AUTH_TYPE is OAUTH or IDP.                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Optional            | ""            | Secret         |
| IDP_TOKEN_URL      | The token endpoint URL of your Identity Provider. Required when AUTH_TYPE is IDP.                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Optional            | ""            | Variable       |
| IDP_SCOPE          | The scope to request from the IDP token endpoint. Optional when AUTH_TYPE is IDP.                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Optional            | ""            | Variable       |
| IDP_AUDIENCE       | The audience to request from the IDP token endpoint. Optional when AUTH_TYPE is IDP.                                                                                                                                                                                                                                                                                                                                                                                                                                                             | Optional            | ""            | Variable       |
| WEBAPP_ID          | Use the Web App ID that you want to scan.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Mandatory           | ""            | Variable       |
| SCAN_NAME          | Use any name for the scan. The timestamp gets appended automatically.                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Mandatory           | ""            | Variable       |
| SCAN_TYPE          | This parameter specifies the scan type. Use VULNERABILITY or DISCOVERY as a parameter value.                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Mandatory           | ""            | Variable       |
| AUTH_RECORD        | Use any of the following values: useDefault: The default authentication record for the web app in WAS (if any) is used. other: Use this value to use a specific value for AUTH_RECORD_ID. none: Runs the scan without authentication. It is the default value. Note: If you use none as a parameter value, the scanner will not be able to log into the secured web application tabs and to test the authenticated area of the application.                                                                                                      | Optional            | none          | Variable       |
| AUTH_RECORD_ID     | Use the specific AUTH_RECORD_ID. Note: You must set the value for the AUTH_RECORD parameter as other.                                                                                                                                                                                                                                                                                                                                                                                                                                            | Optional            | ""            | Variable       |
| OPTION_PROFILE     | The option profile contains the various scan settings such as the vulnerability types that should be tested (detection scope), scan intensity, error thresholds, etc. Use any of the following values: useDefault: It uses the default option profile in WAS. It is the default value. other: You can use a specific value for the OPTION_PROFILE_ID parameter.                                                                                                                                                                                  | Optional            | useDefault    | Variable       |
| OPTION_PROFILE_ID  | Use the option profile ID of your choice. Note: You must set the OPTION_PROFILE parameter value as other to use this parameter.                                                                                                                                                                                                                                                                                                                                                                                                                  | Optional            | ""            | Variable       |
| CANCEL_OPTION      | Use any of the following: true: Set this value to true to specify the scan end time. false: The scan will run until it is completed. This is the default value.                                                                                                                                                                                                                                                                                                                                                                                  | Optional            | false         | Variable       |
| CANCEL_HOURS       | Use the numeric value to specify scan duration in hours. The scan is terminated after a specified time. You must set the CANCEL_OPTION parameter value as true to use this parameter.                                                                                                                                                                                                                                                                                                                                                            | Optional            | ""            | Variables      |
| SEVERITY_CHECK     | Use any of the following values: true: This will set the SEVERITY_LEVEL as a failure condition for the scan. false: The SEVERITY_LEVEL is not considered in scan failure.                                                                                                                                                                                                                                                                                                                                                                        | Optional            | false         | Variables      |
| SEVERITY_LEVEL     | Specify the severity level of the vulnerability. You can use any values between 1-5. In Qualys, a severity level of 1 is as considered the least harmful, and a severity level of 5 is considered as most harmful. Note: You can enter only one value as a scan parameter during a scan. The scan will fail the build if it detects the vulnerability of a specified value or greater than that. For example, if you set the severity level to 3, the build will fail if the vulnerability of severity level 3 or more is found during the scan. | Optional            | 0             | Variable       |
| FAIL_ON_SCAN_ERROR | Use true or false as the parameter value. true: When the GitHub plugin initiates the scan and the value for this parameter is set to true, but the WAS module cannot complete the scan due to some issues then the build fails. false: If you set the parameter value as false then the build does not fail due to incomplete scan. The default value for this parameter is false.                                                                                                                                                               | Optional            | false         | Variable       |
| WAIT_FOR_RESULT    | Use any of the following values: true: The plugin waits for the scan results. The default value for this parameter is true. false: The plugin will not wait for the scan results.                                                                                                                                                                                                                                                                                                                                                                | Optional            | true          | Variable       |
| INTERVAL           | Use the numeric value to set the polling interval in minutes to collect the scan data. Ex: 5. By default, it will be 5 Minutes.                                                                                                                                                                                                                                                                                                                                                                                                                  | Optional            | 5             | Variable       |
| TIMEOUT            | Use the numeric value to set the timeout duration in minutes to check the scan results. For example, 60. The default value of TIMEOUT is 350 min. Note: The timeout limit for GitHub-hosted runners is 360 minutes. On GitHub-hosted runners, you cannot run the job for more than 360 minutes. However, in self-hosted runners, there is no limit on timeout, and you can set a timeout for more than 360 minutes.                                                                                                                              | Optional            | 350           | Variable       |
| EXCLUDE            | Use the QIDs separated by commas to exclude them from the scan. For example, 1234, 1345. This will exclude these two QIDs for vulnerability severity level failure conditions.                                                                                                                                                                                                                                                                                                                                                                   | Optional            | ""            | Variable       |
| FILE_TYPE          | This parameter specifies the file format in which user wants the scan report                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Optional            | "PDF"         | Variable       |
| ARTIFACT_RETENTION_DAYS | Number of days (1-90) to retain the `Qualys_WAS_Scan_Result` artifact. The artifact contains the raw scan JSON and the report, which disclose vulnerable URLs and findings, so keep this short. If not set, the repository/organization artifact retention setting applies (GitHub default: 90 days).                                                                                                                                                                                                                                      | Optional            | ""            | Variable       |
| SEND_MAIL          | Controls the "scan complete" email notification sent by the WAS module. true: email is sent (default WAS behavior). false: `sendMail=false` no notification email is sent.                                                                                                                                                                                                                                                                                                                                    | Optional            | true          | Variable       |
Note: The Parameter values given in the above table are case-sensitive.

## Security Recommendations

- **Pin the action version.** Use a release tag Eg.(`Qualys/github-action-qwas@v2.1.0`) or a full commit SHA. The action builds and runs the code at the same ref you pin and what executes.
- **Least privilege.** Set `permissions: contents: read` on the workflow or job. The action never writes to your repository.
- **Store credentials as secrets.** `QUALYS_PASSWORD` and `CLIENT_SECRET` must be GitHub Secrets, not variables.
- **Use HTTPS.** `API_SERVER` must start with `https://`; the action fails fast otherwise.

## Release Notes

### v2.1.0

Security hardening release. Upgrading is recommended for all users; older tags (`v1.x`) continue to build from the `main` branch at run time and do not receive the fixes below.

- **New authentication type `IDP`.** `AUTH_TYPE` now accepts `IDP` for external Identity Provider authentication using the client credentials grant. Requires `CLIENT_ID`, `CLIENT_SECRET`, and `IDP_TOKEN_URL`; `IDP_SCOPE` and `IDP_AUDIENCE` are optional.
- **Action code is now pinned to the version you use.** The action previously checked out its own repository at the default branch (`main`) on every run, regardless of the tag in your `uses:` line. It now checks out the same ref you pinned (tag or commit SHA), into a dedicated `qwas-action/` directory so your repository checkout is no longer overwritten.
- **Maven Wrapper integrity checks.** `distributionSha256Sum` and `wrapperSha256Sum` are set in `.mvn/wrapper/maven-wrapper.properties`; the build refuses to run a tampered Maven distribution or wrapper JAR.
- **HTTPS enforced for `API_SERVER`.** Plain `http://` URLs are rejected before any credentials are sent.
- **New input `ARTIFACT_RETENTION_DAYS`.** Lets you control how long the scan result artifact is kept. Defaults to your repository/organization setting, so existing workflows are unaffected.
- **New input `SEND_MAIL`.** Controls the scan-complete email notification. Default `true` (email sent). Set to `false` to pass `sendMail=false` and disable notification emails.
- `actions/checkout` bumped to `v4`.