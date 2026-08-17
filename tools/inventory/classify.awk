# Classify an env variable name as secret, public, constant, or review.
#
# This is the `classification` field from the catalog spec (HANDOFF.md 6.1), and
# it exists because of the founder's own rule: a value is not an environment
# variable until it has to be. On findmyhooks that rule took 46 variables down
# to 24 real secrets. The point of running it across every project is to find
# out how small the vault actually needs to be.
#
# Input:  project \t relpath \t name \t len \t class \t kind
# Output: the same, plus \t classification
#
# Order matters. The first rule that matches wins, and the rules are ordered
# most-certain first.

function classify(name, cls,   n) {
  n = toupper(name)

  # 1. Public by construction. These prefixes are compiled into a browser
  #    bundle by the framework, so the value is served to every visitor. It
  #    cannot be a secret no matter what it is named, and a name like
  #    NEXT_PUBLIC_STRIPE_SECRET_KEY is a naming error, not a credential.
  if (n ~ /^(NEXT_PUBLIC_|VITE_|PUBLIC_|REACT_APP_|NUXT_PUBLIC_|EXPO_PUBLIC_|VUE_APP_|GATSBY_)/)
    return "public"

  # 2. Secret. Anything that authenticates, signs, or grants access.
  if (n ~ /(^|_)(SECRET|PASSWORD|PASSWD|TOKEN|APIKEY|CREDENTIAL|CREDENTIALS|PRIVATE|SIGNING|SALT|PEPPER|JWT|SERVICE_ROLE)($|_)/)
    return "secret"
  if (n ~ /_SECRET/ || n ~ /_DSN$/ || n ~ /SERVICE_ROLE/)
    return "secret"
  # A publishable or public key is deliberately shareable; a key id names a
  # credential without being one.
  if (n ~ /_KEY$/ && n !~ /(PUBLIC|PUBLISHABLE)/)
    return "secret"
  # Connection strings carry a password inside the URL, so the _URL suffix rule
  # below must not claim them.
  if (n ~ /^(DATABASE|DB|POSTGRES|POSTGRESQL|MYSQL|MONGO|MONGODB|REDIS|AMQP|RABBITMQ|CLICKHOUSE|SUPABASE)_(URL|URI)$/)
    return "secret"
  # A webhook URL is a bearer credential: whoever holds it can post as you.
  if (n ~ /(SLACK|DISCORD|TEAMS)_WEBHOOK/)
    return "secret"

  # 3. Decided constant. Belongs in a constants module in source, not in a
  #    dashboard row a human has to retype per deployment.
  if (n ~ /^(PORT|HOST|HOSTNAME|NODE_ENV|ENV|ENVIRONMENT|LOG_LEVEL|TZ|LANG|DEBUG|CI|APP_ENV|RAILS_ENV)$/)
    return "constant"
  if (n ~ /_(PORT|BASE_URL|API_URL|ENDPOINT|MODEL|REGION|BUCKET|VERSION|TIMEOUT|LIMIT|ENABLED|MAX|MIN|COUNT|SIZE|MODE|LEVEL|NAME|DIR|PATH|DOMAIN|SENDER|CURRENCY|LOCALE|CODE|PREFIX|SUFFIX|TTL|INTERVAL|RETRIES|CONCURRENCY|WORKERS)$/)
    return "constant"
  # A bare number or an empty value is almost never a credential.
  if (cls == "digits" || cls == "empty")
    return "constant"

  return "review"
}

BEGIN { FS = "\t"; OFS = "\t" }
{ print $1, $2, $3, $4, $5, $6, classify($3, $5) }
