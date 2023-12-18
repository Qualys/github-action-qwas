# Qualys WAS GitHub Action


## Description



## How to use the Qualys WAS GitHub Action

1. Visit [GitHub configuration a workflow](https://help.github.com/en/actions/configuring-and-managing-workflows/configuring-a-workflow) to enable Github Action in your repository.
2. Subscribe to Qualys CloudView and obtain Qualys credentials.
3. Create GitHub Secrets for Qualys URL, Qualys Username and Qualys Password.
   Refer to [Encrypted secrets](https://docs.github.com/en/actions/reference/encrypted-secrets) for more details on how to setup secrets.
4. Configure your workflow. In the actions section use `Qualys/github_action_qwas@main`
   Note: the `actions/checkout` step is required to run before the scan action, otherwise the action does not have access to the IaC files to be scanned.
5. Optionally, supply parameters to customize GitHub action behaviour.

## Usage Examples

### Scan Web App in your repository on push event

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
            uses: Qualys/github_action_qwas@main
            id: was
            with:
              PLATFORM: ${{ vars.PLATFORM }}
              API_SERVER: ${{ secrets.API_SERVER }}
              QUALYS_USERNAME: ${{ secrets.QUALYS_USERNAME }}
              QUALYS_PASSWORD: ${{ secrets.QUALYS_PASSWORD }}
              USE_PROXY: ${{ vars.USE_PROXY }}
              PROXY_SERVER: ${{ secrets.PROXY_SERVER }}
              PROXY_PORT: ${{ vars.PROXY_PORT }}
              PROXY_USERNAME: ${{ secrets.PROXY_USERNAME }}
              PROXY_PASSWORD: ${{ secrets.PROXY_PASSWORD }}
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
              IS_FAIL_ON_QID_FOUND: ${{ vars.IS_FAIL_ON_QID_FOUND }}
              QID_LIST: ${{ vars.QID_LIST }}
              EXCLUDE: ${{ vars.EXCLUDE }}
              FAIL_ON_SCAN_ERROR: ${{ vars.FAIL_ON_SCAN_ERROR }}
              WAIT_FOR_RESULT: ${{ vars.WAIT_FOR_RESULT }}

#      Checkout the repository to download the scan result in your repository.
#      if repository is private then add PAT (personal access token) token in the checkout step.:
          - name: checkout code
            uses: actions/checkout@v3
            with:
             repository: GITHUB_USERNAME/REPOSITORY_NAME
             ref: BRANCH_NAME
             path: ./
             PAT: ${{ secrets.ACCESS_TOKEN }}

          - name: Download Result
            uses: actions/download-artifact@v3
            with:
             name: Qualys_WAS_Scan_Result
             path: PATH_TO_TARGET_DIRECTORY 
```

### Scan Web App in your repository on pull request event

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
        uses: Qualys/github_action_qwas@main
        id: was
        with:
          PLATFORM: ${{ vars.PLATFORM }}
          API_SERVER: ${{ secrets.API_SERVER }}
          QUALYS_USERNAME: ${{ secrets.QUALYS_USERNAME }}
          QUALYS_PASSWORD: ${{ secrets.QUALYS_PASSWORD }}
          USE_PROXY: ${{ vars.USE_PROXY }}
          PROXY_SERVER: ${{ secrets.PROXY_SERVER }}
          PROXY_PORT: ${{ vars.PROXY_PORT }}
          PROXY_USERNAME: ${{ secrets.PROXY_USERNAME }}
          PROXY_PASSWORD: ${{ secrets.PROXY_PASSWORD }}
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
          IS_FAIL_ON_QID_FOUND: ${{ vars.IS_FAIL_ON_QID_FOUND }}
          QID_LIST: ${{ vars.QID_LIST }}
          EXCLUDE: ${{ vars.EXCLUDE }}
          FAIL_ON_SCAN_ERROR: ${{ vars.FAIL_ON_SCAN_ERROR }}
          WAIT_FOR_RESULT: ${{ vars.WAIT_FOR_RESULT }}

#      Checkout the repository to download the scan result in your repository.
#      if repository is private then add PAT (personal access token) token in the checkout step.:
      - name: checkout code
        uses: actions/checkout@v3
        with:
           repository: GITHUB_USERNAME/REPOSITORY_NAME
           ref: BRANCH_NAME
           path: ./
           PAT: ${{ secrets.ACCESS_TOKEN }}

      - name: Download Result
        uses: actions/download-artifact@v3
        with:
           name: Qualys_WAS_Scan_Result
           path: PATH_TO_TARGET_DIRECTORY
```

### Scan Web App in your repository on manual trigger

```yaml
name: Qualys IAC Scan 
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
        uses: Qualys/github_action_qwas@main
        id: was
        with:
          PLATFORM: ${{ vars.PLATFORM }}
          API_SERVER: ${{ secrets.API_SERVER }}
          QUALYS_USERNAME: ${{ secrets.QUALYS_USERNAME }}
          QUALYS_PASSWORD: ${{ secrets.QUALYS_PASSWORD }}
          USE_PROXY: ${{ vars.USE_PROXY }}
          PROXY_SERVER: ${{ secrets.PROXY_SERVER }}
          PROXY_PORT: ${{ vars.PROXY_PORT }}
          PROXY_USERNAME: ${{ secrets.PROXY_USERNAME }}
          PROXY_PASSWORD: ${{ secrets.PROXY_PASSWORD }}
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
          IS_FAIL_ON_QID_FOUND: ${{ vars.IS_FAIL_ON_QID_FOUND }}
          QID_LIST: ${{ vars.QID_LIST }}
          EXCLUDE: ${{ vars.EXCLUDE }}
          FAIL_ON_SCAN_ERROR: ${{ vars.FAIL_ON_SCAN_ERROR }}
          WAIT_FOR_RESULT: ${{ vars.WAIT_FOR_RESULT }}
          
#      Checkout the repository to download the scan result in your repository.
#      if repository is private then add PAT (personal access token) token in the checkout step.:
      - name: checkout code
        uses: actions/checkout@v3
        with:
           repository: GITHUB_USERNAME/REPOSITORY_NAME
           ref: BRANCH_NAME
           path: ./
           PAT: ${{ secrets.ACCESS_TOKEN }}

      - name: Download Result
        uses: actions/download-artifact@v3
        with:
           name: Qualys_WAS_Scan_Result
           path: PATH_TO_TARGET_DIRECTORY
```

## Prerequisites for Qualys WAS GithHub Action
1. Valid Qualys Credentials and subscription of Qualys CloudView module.
2. Use of `actions/checkout@v3` with ` fetch-depth: 0` before calling Qualys WAS GitHub action.
3. `PLATFORM, API_SERVER, QUALYS_USERNAME, QUALYS_PASSWORD, PROXY_SERVER, PROXY_USERNAME, PROXY_PASSWORD` to be added in `secrets` and remaining to be added in the `repository variables` of Qualys WAS GitHub action.

## GitHub action Parameters

| Parameter            | Description | Required | Default | Type            |
|----------------------| -------------------------------------------------------------------------------------------------------- |----------|---------|-----------------|
| PLATFORM             |   | YES      | ""      | Input parameter |
| API_SERVER           |   | YES      | ""      | Input parameter |
| QUALYS_USERNAME      |   | YES      | ""      | Input parameter |
| QUALYS_PASSWORD      |   | YES      | ""      | Input parameter |
| USE_PROXY            |   | YES      | false   | Input parameter |
| PROXY_SERVER         |   | NO       | ""      | Input parameter |
| PROXY_PORT           |   | NO       | 0       | Input parameter |
| PROXY_USERNAME       |   | NO       | ""      | Input parameter |
| PROXY_PASSWORD       |   | NO       | ""      | Input parameter |
| WEBAPP_ID            |   | YES      | ""      | Input parameter |
| SCAN_NAME            |   | YES      | ""      | Input parameter |
| SCAN_TYPE            |   | YES      | ""      | Input parameter |
| AUTH_RECORD          |   | NO       | false   | Input parameter |
| AUTH_RECORD_ID       |   | NO       | ""      | Input parameter |
| OPTION_PROFILE       |   | NO       | false   | Input parameter |
| OPTION_PROFILE_ID    |   | NO       | ""      | Input parameter |
| CANCEL_OPTION        |   | NO       | false   | Input parameter |
| CANCEL_HOURS         |   | NO       | ""      | Input parameter |
| SEVERITY_CHECK       |   | NO       | false   | Input parameter |
| SEVERITY_LEVEL       |   | NO       | 0       | Input parameter |
| FAIL_ON_SCAN_ERROR   |   | NO       | false   | Input parameter |
| WAIT_FOR_RESULT      |   | NO       | true    | Input parameter |
 
