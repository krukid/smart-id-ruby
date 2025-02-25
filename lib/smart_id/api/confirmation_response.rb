module SmartId::Api
  class ConfirmationResponse
    RUNNING_STATE = "RUNNING"
    COMPLETED_STATE = "COMPLETE"
    USER_REFUSED_RESULT = "USER_REFUSED"
    USER_TIMEOUT_RESULT = "TIMEOUT"

    attr_reader :body
    
    def initialize(response_body, hashed_data)
      @body = response_body

      raise SmartId::UserRefusedError if end_result == USER_REFUSED_RESULT
      raise SmartId::UserTimeoutError if end_result == USER_TIMEOUT_RESULT

      validate!(hashed_data) unless confirmation_running?
    end

    def confirmation_running?
      state == RUNNING_STATE
    end

    def state
      @body["state"]
    end

    def end_result
      @body.dig("result", "endResult")
    end

    def document_number
      @body.dig("result", "documentNumber")
    end

    def certificate_level
      @body.dig("cert", "certificateLevel")
    end

    def certificate
      @certificate ||= SmartId::AuthenticationCertificate::Certificate.new(@body.dig("cert", "value"))
    end

    def signature_algorithm
      @body.dig("signature", "algorithm")
    end

    def signature
      @body.dig("signature", "value")
    end

    def ignored_properties
      @body["ignoredProperties"]
    end

    private
    
    def validate!(hashed_data)
      SmartId::Utils::CertificateValidator.validate!(hashed_data, signature, certificate)
    end
  end
end
