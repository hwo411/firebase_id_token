module FirebaseIdToken
  # Deals with verifying if a given Firebase ID Token is signed by one of the
  # Google's x509 certificates that Firebase uses.
  #
  # Also checks if the resulting JWT payload hash matches with:
  # + `exp` Expiration time
  # + `iat` Issued at time
  # + User's Firebase Project ID
  # + Non-empty UID
  #
  # ## Verifying a Firebase ID Token
  #
  # *Be sure to configure the gem to set your Firebase Project ID and a Redis
  # server before move any forward.*
  #
  # **See the README for a complete guide.**
  #
  # **WARNING:** Trying to verify a token without any certificate saved in
  # Redis certificates database raises a {Exceptions::NoCertificatesError}.
  #
  # @example
  #   FirebaseIdToken::Signature.verify(thrusty_token)
  #   => {"iss"=>"https://securetoken.google.com/your-project-id", [...]}
  #
  #   FirebaseIdToken::Signature.verify(fake_token)
  #   => nil
  #
  # @see Signature#verify
  class Signature
    # Pre-default JWT algorithm parameters as recommended
    # [here](https://goo.gl/uOK5Jx).
    JWT_DEFAULTS = { algorithm: 'RS256', verify_iat: true }

    # Returns the decoded JWT hash payload of the Firebase ID Token if the
    # signature in the token matches with one of the certificates downloaded
    # by {FirebaseIdToken::Certificates.request}, returns `nil` otherwise.
    #
    # It will also return `nil` when it fails in checking if all the required
    # JWT fields are valid, as recommended [here](https://goo.gl/yOrZZX) by
    # Firebase oficial documentation.
    #
    # Note that it will raise a {Exceptions::NoCertificatesError} if the Redis
    # certificates database is empty. Ensure to call {Certificates.request}
    # before, ideally in a background job if you are using Rails.
    # @return [nil, Hash]
    def self.verify(jwt_token)
      payload = new(jwt_token).verify

      payload if payload['verified']
    end

    def self.verify_anyway(jwt_token)
      new(jwt_token).verify
    end

    # Loads attributes: `:project_ids` from {FirebaseIdToken::Configuration},
    # and `:kid`, `:jwt_token` from the related `jwt_token`.
    # @param [String] jwt_token Firebase ID Token
    def initialize(jwt_token)
      @jwt_errors = []
      @project_ids = FirebaseIdToken.configuration.project_ids
      @kid = extract_kid(jwt_token)
      @jwt_token = jwt_token
    end

    # @see Signature.verify
    def verify
      certificate = FirebaseIdToken::Certificates.find(@kid)
      jwt_options = certificate.nil? ? {} : JWT_DEFAULTS
      cert_key = certificate.public_key if certificate

      if certificate || none?
        payload = decode_jwt_payload(@jwt_token, cert_key, jwt_options)
        @jwt_errors << 'empty payload after decode' unless payload

        payload = authorize(payload)
        @jwt_errors << 'empty payoad after authorize' unless payload
      end

      # not nil in _anyway methos
      result = payload || {}
      result['verified'] = true

      # empty non-verified payload if verification failed
      # mark as non-verified if unsigned
      if none?
        result['verified'] = false
        @jwt_errors << 'no KID determined'
      end

      unless payload
        result['verified'] = false
        @jwt_errors << 'no payload extracted'
      end


      result['jwt_errors'] = @jwt_errors

      result
    end

    private

    def none?
      !@kid || @kid == 'none'
    end

    def extract_kid(jwt_token)
      JWT.decode(jwt_token, nil, false).last['kid']
    rescue StandardError => e
      @jwt_errors << e.to_s
      'none'
    end

    def decode_jwt_payload(token, cert_key, jwt_options)
      JWT.decode(token, cert_key, !cert_key.nil?, jwt_options).first
    rescue StandardError => e
      @jwt_errors << e.to_s
      nil
    end

    def authorize(payload)
      @jwt_errors << 'Attempt to authorize empty payload' && return unless payload
      @jwt_errors << 'Failed to authorize' && return unless authorized?(payload)

      payload
    end

    def authorized?(payload)
      check = still_valid?(payload)
      @jwt_errors << 'token expired (exp and iat check)' && return unless check

      check = @project_ids.include?(payload['aud'])
      @jwt_errors << 'project identity failed (aud check)' && return unless check

      check = issuer_authorized?(payload)
      @jwt_errors << 'project identity failed (iss check)' && return unless check

      check = !payload['sub'].empty?
      @jwt_errors << 'payload sub empty (sub check)' && return unless check

      true
    end

    def still_valid?(payload)
      now = Time.now.to_i

      check = payload['exp'].to_i >= now
      @jwt_errors << "exp[#{payload['exp'].to_i}] > now[#{now}]" && return unless check

      check = payload['iat'].to_i <= now
      @jwt_errors << "iat[#{payload['iat'].to_i}] < now[#{now}]" && return unless check

      true
    end

    def issuer_authorized?(payload)
      issuers = @project_ids.map { |i| "https://securetoken.google.com/#{i}" }
      issuers.include? payload['iss']
    end
  end
end
