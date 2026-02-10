# AFAS Embed - Flask

This Flask application serves as a secure middleware for embedding custom web applications within [AFAS InSite](https://www.afas.nl/software/insite) or [AFAS OutSite](https://www.afas.nl/software/outsite).

It handles the secure token exchange required by AFAS to validate the embedded session immediately upon loading.

## Features

*   **OAuth Code Exchange**: Automatically exchanges the `code` passed by AFAS iframe for a valid User Token.
*   **Secure Session Management**: Establishes a secure, HTTPOnly, SameSite=None cookie session usable within the iframe.
*   **IP Binding**: Binds user sessions to their client IP address to prevent session hijacking.
*   **Security Headers**: Implements rigorous CSP, HSTS, and other security headers to run safely in an embedded context.
*   **Azure Ready**: Configured for easy deployment to Azure Web Apps (Linux).

## Prerequisites

*   Python 3.9+
*   An AFAS Environment with an InSite portal.
*   An **InSite Page** or **OutSite Page** configured to embed this application.

## Configuration

You must set the following environment variables:

| Variable | Description |
| :--- | :--- |
| `AFAS_SECRET` | The shared secret provided by your AFAS environment for the specific InSite page or connector. |
| `FLASK_APP` | Set to `app.py` |

## Local Development

1.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

2.  **Set Environment Variables**:
    ```bash
    # Windows PowerShell
    $env:AFAS_SECRET="your_secret_here"
    ```

3.  **Run the Server**:
    ```bash
    flask run
    ```
    *Note: For AFAS to connect to your local machine, you will need a tunnel service like ngrok.*

## Deployment (Azure Web App)

This project is structured for standard deployment to Azure App Service (Python/Linux).
1.  Push this repository to GitHub/Azure DevOps.
2.  Connect your Azure Web App to the repository.
3.  Set the `AFAS_SECRET` in the Azure Web App **Configuration** -> **Application Settings**.

## Project Structure

*   `app.py`: Main Flask application entry point and route handlers.
*   `AfasService.py`: Handles communication with AFAS APIs.
*   `utils.py`: Helper functions for security and session management.
*   `templates/`: HTML templates for the frontend.
*   `static/`: Static assets (JS/CSS).
