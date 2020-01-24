# swaglyrics-backend
Server side code to make an issue on the [main repo](https://github.com/SwagLyrics/SwagLyrics-For-Spotify) when the 
program encounters a song it can't fetch lyrics for. 

Works using the GitHub API and Flask.

The [main program](https://github.com/SwagLyrics/SwagLyrics-For-Spotify/blob/fbe9428e3458e6cce1396133b84c229ccd974a9e/swaglyrics/cli.py#L57) is configured to send a POST request to the server.

Need to document and add unit testing.

### Rate Limits
In order to prevent spam and/or abuse of endpoints, rate limiting has been set such that it wouldn't affect a normal 
user.

Since SwagLyrics checks for track change every 5 seconds, requests on endpoints `/stripper` and `/unsupported` are 
allowed once per 5 seconds only.

### Sponsors
[![PythonAnywhere](https://www.pythonanywhere.com/static/anywhere/images/PA-logo-small.png)](https://www.pythonanywhere.com/)

swaglyrics-backend is proudly sponsored by [PythonAnywhere](https://www.pythonanywhere.com/).

### Installation

These instructions are also in `docs/getting-started.md`

You'll need a couple of things to run swaglyrics-backend on your machine.

Set these as environment variables:

- SWAG_APPID : Your [Github App Private Key](https://developer.github.com/apps/building-github-apps/authenticating-with-github-apps/#generating-a-private-key)
- WEBHOOK_SECRET : Your [Github App Webhook Secret](https://developer.github.com/webhooks/securing/#setting-your-secret-token)
- C_ID : Your [Spotify Client ID](https://developer.spotify.com/documentation/general/guides/app-settings/)
- SECRET : Your [Spotify Client Secret](https://developer.spotify.com/documentation/general/guides/app-settings/)
- USERNAME : Your github username
- PASSWD : Your github password
- DB_PWD : A password for the database

Configure `issue_maker.py` to be the flask app on your platform:

Windows:

`set FLASK_APP=issue_maker.py`

Optionally set debug mode with `set FLASK_DEBUG=1`

Linux/Mac:

`export FLASK_APP=issue_maker.py`

Optionally set debug mode with `export FLASK_DEBUG=1`

Run the app:

`flask run`
