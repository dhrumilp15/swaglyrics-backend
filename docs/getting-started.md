# Getting Started with SwagLyrics Backend

## Installation

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