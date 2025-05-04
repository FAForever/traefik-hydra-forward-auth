# Traefik <-> Hydra Middleware for forward authentication

## Architecture background
The FAForever project uses [Traefik](https://traefik.io/) as its reverse proxy of choice and
[Ory Hydra](https://www.ory.sh/hydra) as the OAuth2 api.

The more services we add to the architecture, the more services need to implement token verification logic.
So far we used JWTs with embedded roles in the extension of the token. However, this brings some drawbacks on the
lifetime and their invalidation. This is why the Hydra docs suggest to use Opaque tokens instead. Still, we do not want
to implement the token introspection into every service when there can be a centralized solution.

## Features
The Traefik [ForwardAuth middleware](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) allows us to add a
middleware (the application in this repo) to run the authentication and also add new headers.

This app sets the following headers, when the middleware is used:
* X-User-Id
* X-User-Name
* X-User-Roles (whitespace separated)
* X-Client-Id
* X-Client-Scopes (whitespace separated)

There are 2 modes, that can be used as separate Traefik middlewares (see `compose.yaml` file for reference):
* `/enforce-auth` requires a valid authentication Bearer token and returs 401 otherwise
* `/enrich-auth` provides authentication headers only, if an authentication header is present and valid

## Testing
You can test the cases with the `compose.yaml`:

```curl
# Successful authentication on /enforce-auth
curl -v --location --request POST 'localhost:8080' \
--header 'Host: whoami-enforce.localhost' \
--header 'Authorization: Bearer test'

# Missing authentication fails on /enforce-auth
curl -v --location --request POST 'localhost:8080' \
--header 'Host: whoami-enforce.localhost'

# Successful authentication on /enrich-auth
curl -v --location --request POST 'localhost:8080' \
--header 'Host: whoami-enrich.localhost' \
--header 'Authorization: Bearer test'

# Missing authentication passes on /enrich-auth
curl -v --location --request POST 'localhost:8080' \
--header 'Host: whoami-enrich.localhost'

# No header injection possible on present authentication
curl -v --location --request POST 'localhost:8080' \
--header 'Host: whoami-enrich.localhost' \
--header 'X-User-Id: 666' \
--header 'Authorization: Bearer test'

# No header injection possible on missing authentication
curl -v --location --request POST 'localhost:8080' \
--header 'Host: whoami-enrich.localhost' \
--header 'X-User-Id: 666'
```

