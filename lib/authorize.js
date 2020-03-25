/**
 * Checks the `Authorization` header for a JWT and verifies
 * that it is legitimate and valid before allowing the
 * request to proceed.
 */

const errors = require('@feathersjs/errors')
const jwt = require('jsonwebtoken')
const rp = require('request-promise')

module.exports = ({
  // These two parameters allow users to customize which models/services
  // they want to use with this hook
  userService = 'users',
  keysService = 'keys',
  // the actual hook
  authorize = async (context) => {
    // Throw if the hook is being called from an unexpected location.
    if (context.type !== 'before')
      throw new errors.NotAuthenticated('`authorize()` can only be used as a `before` hook.', context)

    // get the Authorization header
    const header = (context.params.headers || {}).authorization || null

    // throw an error if the Authorization header is not set
    if (!header) throw new errors.NotAuthenticated('`Authorization` header not set.', context)

    // extract the raw token from the header
    const currentToken = header.replace('Bearer ', '').trim()

    // decode it
    let token = jwt.decode(currentToken, { complete: true })

    // throw an error if the token was malformed or missing
    if (!token) throw new errors.NotAuthenticated('The token was malformed or missing.')

    // get the user ID from the token payload
    let query = {$limit: 1};
    query[auth0Field] = token.payload.sub;
    // check to see if we have a member with this ID in the database
    let member;
    try {
      member = await context.app.service(userService).find({
        paginate: false,
        query: query
      }).then(results => {
        if (results[0]) return results[0]
        throw 'member does not exist'
      })
    } catch (err) {
      // throw an error if no such member exists
      throw new errors.NotAuthenticated('No member with this ID exists.', context)
    }

    // if the member already has a valid, current token, stop here
    if (member.currentToken && member.currentToken === currentToken) return context

    // otherwise, get the kid from the token header
    const kid = token.header.kid

    // create a JWKS retrieval client
    const client = getJWKS(context.app.get('authentication').jwksUri);
    // get the signing key from the JWKS endpoint at Auth0
    const key = await getKey(kid, context.app.service(keysService), client)

    // verify the raw JWT
    try {
      jwt.verify(currentToken, key, context.app.get('authentication').jwtOptions);
    } catch (err) {
      throw new errors.NotAuthenticated('Token could not be verified.', err.message)
    }

    // OK! The JWT is valid, store it in the member profile
    // (It's okay if this fails)
    context.app.service(userService).patch(
      member.id,
      { currentToken }
    )

    // If we made it this far, we're all good!
    return context
  },
  /**
   * Takes a JWKS endpoint URI and returns a function that can retrieve an
   * array of JWKs, i.e. a JWKS. The resulting function may throw any of
   * [the errors described here]{@link https://github.com/request/promise-core/blob/master/lib/errors.js}
   * 
   * @param   {string}   uri The URI of the JWKS endpoint
   * @returns {function}     A function that can retrieve a JWKS from the endpoint
   */
  getJWKS = uri => () => rp({ uri, json: true }),
  /**
   * Takes a JWK object and returns a valid key in PEM format. Throws
   * a GeneralError if there are no x5c items stored on the JWK.
   * 
   * @param   {string}       jwk The JWK to be parsed
   * @returns {string}           The key in PEM format from the first x5c entry
   * @throws  {GeneralError}     Throws a GeneralError if there are no x5c items
   */
  x5cToPEM = jwk => {
    if (!jwk.x5c.length > 0) throw new errors.GeneralError('Stored JWK has no x5c property.')
    const lines = jwk.x5c[0].match(/.{1,64}/g).join('\n')
    return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----\n`
  },
  /**
   * Takes a `kid`, a reference to an in-memory Feathers service (`svc`)
   * for storing JWKs, and a `client` for retrieving signing keys from a
   * JWKS endpoint. Returns a valid signing key in PEM format or throws
   * a `SigningKeyNotFoundError`. If a key is successfully retrieved from
   * the endpoint, it tries to store this value using the `svc`.
   * 
   * @async
   * @param   {string}       kid        The `kid` for the JWK to be retrieved
   * @param   {object}       svc        The Feathers service used to store JWKs in memory
   * @param   {function}     jwksClient A function that takes a `kid` and returns a key
   * @returns {string}                  The retrieved signing key in PEM format
   * @throws  {GeneralError}            Thrown by the `client` if `kid` is not found
   */
  getKey = async (kid, svc, jwksClient) => {
    try {
      // get the signing key from the in-memory service, if it exists
      const storedKey = await svc.find({ query: { kid } }).then(keys => keys.data[0])

      // if the storedKey exists, return it
      if (storedKey) return x5cToPEM(storedKey)
    } catch (err) {
      // nothing to see here. please move along...
    }

    // otherwise, we need to get it from our JWKS endpoint
    let jwk
    try {
      const jwks = await jwksClient()
      jwk = jwks.keys.find(k => k.kid === kid)
    } catch (err) {
      // throw an error if we still don't have a signing key
      throw new errors.GeneralError('Could not retrieve JWKS', err)
    }

    // throw an error if there were no JWKs that contained our kid
    if (!jwk) throw new errors.GeneralError('Could not find a JWK matching given kid')

    // get the signing key from the retrieved JWK
    const key = x5cToPEM(jwk)

    // store the jwk in our in-memory service
    try { svc.create(jwk) } catch (e) { /* no problem if this fails */ }

    // and return the key
    return key
  }
} = {}) => ({
  userService,
  keysService,
  authorize,
  getJWKS,
  x5cToPEM,
  getKey
})
