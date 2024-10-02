const badge = (() => {
    const tokenKey = "jwt_token";

    /**
     * Set the redirect uris of an owned application
     * @param {string} applicationId
     * @param {string[]} redirectUris
     * @returns A success result { sucess:true } or a failure { success:false, message:string }
     */
    async function postRedirectUris(applicationId, redirectUris) {
        try {
            const response = await fetch("/api/applications/" + applicationId + "/redirect-uris", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(redirectUris)
            });

            if (response.ok) {
                return { success: true };
            } else {
                const error = await response.json();
                return { success: false, message: error.detail || "Failed to post redirect uris" };
            }
        } catch (error) {
            return { success: false, message: "An error occurred. Please try again." };
        }
    }

    /**
     * Gets a list of redirect URIs associated with an application id. Only works for owned application ids
     * @param {string} applicationId
     * @returns A success result { sucess:true, redirectUris: [] } or a failure { success:false, message:string }
     */
    async function getRedirectUris(applicationId) {
        try {
            const response = await fetch("/api/applications/" + applicationId + "/redirect-uris", {
                method: "GET",
                headers: {
                    "Content-Type": "application/json"
                }
            });

            if (response.ok) {
                const redirectUrisList = await response.json();
                return { success: true, redirectUris: redirectUrisList };
            } else {
                const error = await response.json();
                return { success: false, message: error.detail || "Fetch redirect uris failed" };
            }
        } catch (error) {
            return { success: false, message: "An error occurred. Please try again." };
        }
    }

    /**
     * Delete client secret
     * @param {string} clientSecretId
     * @param {string} applicationId
     * @returns A success result { sucess:true } or a failure { success:false, message:string }
     */
    async function deleteClientSecret(applicationId, clientSecretId) {
        try {
            const response = await fetch("/api/applications/" + applicationId + "/secrets/" + clientSecretId, {
                method: "DELETE",
                headers: {
                    "Content-Type": "application/json"
                }
            });

            if (response.ok) {
                return { success: true };
            } else {
                const error = await response.json();
                return { success: false, message: error.detail || "Client secret deletion failed" };
            }
        } catch (error) {
            return { success: false, message: "An error occurred. Please try again." };
        }
    }

    /**
     * Create client secret
     * @param {string} applicationId
     * @returns A success result { sucess:true, clientSecret:[] } or a failure { success:false, message:string }
     */
    async function createClientSecret(applicationId) {
        try {
            const response = await fetch("/api/applications/" + applicationId + "/secrets", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                }
            });

            if (response.ok) {
                const clientSecret = await response.json();
                return { success: true, clientSecret: clientSecret };
            } else {
                const error = await response.json();
                return { success: false, message: error.detail || "Client secret creation failed" };
            }
        } catch (error) {
            return { success: false, message: "An error occurred. Please try again." };
        }
    }

    /**
     * Gets a list of secrets associated with an application id. Only works for owned application ids
     * @param {string} applicationId
     * @returns A success result { sucess:true, secrets: [] } or a failure { success:false, message:string }
     */
    async function getClientSecrets(applicationId) {
        try {
            const response = await fetch("/api/applications/" + applicationId + "/secrets", {
                method: "GET",
                headers: {
                    "Content-Type": "application/json"
                }
            });

            if (response.ok) {
                const secretsList = await response.json();
                return { success: true, secrets: secretsList };
            } else {
                const error = await response.json();
                return { success: false, message: error.detail || "Fetch secrets failed" };
            }
        } catch (error) {
            return { success: false, message: "An error occurred. Please try again." };
        }
    }

    /**
     * Get application details of an application registered under current user
     * @param {string} applicationId 
     * @returns A success result { sucess:true, applications: [] } or a failure { success:false, message:string }
     */
    async function getApplication(applicationId) {
        try {
            const response = await fetch("/api/applications/" + applicationId, {
                method: "GET",
                headers: {
                    "Content-Type": "application/json"
                }
            });

            if (response.ok) {
                const application = await response.json();
                return { success: true, application: application };
            } else {
                const error = await response.json();
                return { success: false, message: error.detail || "Fetch application failed" };
            }
        } catch (error) {
            return { success: false, message: "An error occurred. Please try again." };
        }
    }

    /**
     * Get a list of applications registered under current user
     * @returns A success result { sucess:true, applications: [] } or a failure { success:false, message:string }
     */
    async function getApplications() {
        try {
            const response = await fetch("/api/applications/me", {
                method: "GET",
                headers: {
                    "Content-Type": "application/json"
                }
            });

            if (response.ok) {
                const applicationList = await response.json();
                return { success: true, applications: applicationList };
            } else {
                const error = await response.json();
                return { success: false, message: error.detail || "Fetch applications failed" };
            }
        } catch (error) {
            return { success: false, message: "An error occurred. Please try again." };
        }
    }

    /**
     * Creates a new application with specified name
     * @param {any} applicationName
     * @returns A success result { sucess:true } or a failure { success:false, message:string }
     */
    async function createApplication(applicationName) {
        try {
            const response = await fetch("/api/applications/create", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ name: applicationName })
            });

            if (response.ok) {
                return { success: true };
            } else {
                const error = await response.json();
                return { success: false, message: error.detail || "Application creation failed" };
            }
        } catch (error) {
            return { success: false, message: "An error occurred. Please try again." };
        }
    }

    /**
     * Requests user information
     * @returns An success result { sucess:true, user:object } or a failure { success:false, message:string }
     */
    async function getUserDetails() {
        try {
            const response = await fetch("/api/users/me", {
                method: "GET",
                headers: {
                    "Content-Type": "application/json"
                }
            });

            if (response.ok) {
                const user = await response.json();
                return { success: true, user };
            } else {
                const error = await response.json();
                return { success: false, message: error.detail || "Fetch user details failed" };
            }
        } catch (error) {
            return { success: false, message: "An error occurred. Please try again." };
        }
    }

    function removeJwtToken() {
        document.cookie = `${tokenKey}=; Max-Age=0; Secure; HttpOnly; SameSite=Strict`;
    }

    /**
     * Verifies the existence of a valid JWT token
     * @returns true is the user is authenticated
     */
    async function isAuthenticated() {
        var response = await getUserDetails();
        return response.success;
    }

    /**
     * Perform login on Badge
     * @param {string} username
     * @param {string} password
     * @returns A success result { sucess:true, token:string } or a failure { success:false, message:string }
     */
    async function login(username, password) {
        try {
            const response = await fetch("/api/users/login", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ username: username, password: password })
            });

            if (response.ok) {
                const { token } = await response.text();
                return { success: true, token };
            } else {
                const error = await response.json();
                return { success: false, message: error.detail || "Login failed" };
            }
        } catch (error) {
            return { success: false, message: "An error occurred. Please try again." };
        }
    }

    /**
     * Register account in Badge
     * @param {any} username
     * @param {any} password
     * @returns A success result { sucess:true, token:string } or a failure { success:false, message:string }
     */
    async function register(username, password) {
        try {
            const response = await fetch("/api/users/create", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ username: username, password: password })
            });

            if (response.ok) {
                const { token } = await response.text();
                return { success: true, token };
            } else {
                const error = await response.json();
                return { success: false, message: error.detail || "Registration failed" };
            }
        } catch (error) {
            return { success: false, message: "An error occurred. Please try again." };
        }
    }

    /**
     * Get authorization code for OAuth flow
     * @param {string} clientId
     * @param {string} clientSecret
     * @param {string} scope
     * @param {string} state
     * @param {string} redirectUri
     * @returns Code to be used in OAuth flow to generate a token
     */
    async function authorize(clientId, clientSecret, scope, state, redirectUri) {
        try {
            
            
            const response = await fetch("/api/oauth/authorize", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ clientId: clientId, clientSecret: clientSecret, scope: scope, state: state, redirectUri: redirectUri })
            });

            if (response.ok) {
                const result = await response.json();
                return { success: true, result };
            } else {
                const error = await response.json();
                return { success: false, message: error.detail || "Authorize failed" };
            }
        } catch (error) {
            return { success: false, message: "An error occurred. Please try again." };
        }
    }

    /**
     * Log out current user and return to login page
     */
    function logout() {
        removeJwtToken();
        window.location.href = "/login"; // Redirect to login page after logout
    }

    return {
        login,
        register,
        isAuthenticated,
        logout,
        getUserDetails,
        authorize,
        createApplication,
        getApplications,
        getClientSecrets,
        createClientSecret,
        getRedirectUris,
        postRedirectUris,
        deleteClientSecret,
        getApplication
    };
})();

export default badge;
