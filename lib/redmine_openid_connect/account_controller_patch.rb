module RedmineOpenidConnect
  module AccountControllerPatch
    def login
      domain = OicSession.client_config[:attr_domain].to_s
      if request.post? && domain.present? &&
        [params[:username], User.find_by_login(params[:username]).try(:mails)].join(",").include?(domain)
        return redirect_to oic_login_url
      end

      OicSession.find_by_id(session[:oic_session_id]).try(:destroy)
      super
    end

    def logout
      if OicSession.disabled? || params[:local_login].present?
        return super
      end

      oic_session = OicSession.find(session[:oic_session_id])
      oic_session.destroy
      logout_user
      reset_session
      redirect_to oic_session.end_session_url
    rescue ActiveRecord::RecordNotFound => e
      oic_local_logout
      redirect_to signin_url
    end

    # performs redirect to SSO server
    def oic_login
      if session[:oic_session_id].blank?
        oic_session = OicSession.create
        session[:oic_session_id] = oic_session.id
      else
        begin
          oic_session = OicSession.find session[:oic_session_id]
        rescue ActiveRecord::RecordNotFound => e
          oic_session = OicSession.create
          session[:oic_session_id] = oic_session.id
        end

        if oic_session.complete? && oic_session.expired?
          response = oic_session.refresh_access_token!
          if response[:error].present?
            oic_session.destroy
            oic_session = OicSession.create
            session[:oic_session_id] = oic_session.id
          end
        end
      end

      redirect_to oic_session.authorization_url
    end

    def oic_local_logout
      logout_user
      reset_session
    end

    def oic_local_login
      if params[:code]
        oic_session = OicSession.find(session[:oic_session_id])

        unless oic_session.present?
          return invalid_credentials
        end

        # verify request state or reauthorize
        unless oic_session.state == params[:state]
          flash[:error] = l(:error_invalid_openid_connect_request)
          return redirect_to oic_local_logout
        end

        oic_session.update_attributes!(authorize_params)

        # verify id token nonce or reauthorize
        if oic_session.id_token.present?
          unless oic_session.claims['nonce'] == oic_session.nonce
            flash[:error] = l(:error_invalid_id_token)
            return redirect_to oic_local_logout
          end
        end

        # get access token and user info
        oic_session.get_access_token!
        user_info = oic_session.get_user_info!
        attrs = oic_session.class.attributes

        # verify application authorization
        unless oic_session.authorized?
          return invalid_credentials
        end

        # Check if there's already an existing user
        user = User.find_by_mail(user_info[attrs[:mail]])

        if user.nil?
          user = User.new

          user.login = user_info[attrs[:login]].gsub(/ /, '')
          name       = user_info[attrs[:first]].gsub(/  */, ' ').gsub(/^ /, '').gsub(/ $/, '')
          surname    = user_info[attrs[:last]].gsub(/  */, ' ').gsub(/^ /, '').gsub(/ $/, '')
          mail       = user_info[attrs[:mail]].gsub(/  */, ' ').gsub(/^ /, '').gsub(/ $/, '')
          name       = name.gsub(/ .*/,'') if attrs[:first_comp]
          if attrs[:last_comp]
            surname.gsub!(/^[^ ]* /, '')
            while surname.size > 30
              surname.match?(/^. /) ? surname.gsub!(/^. /,'') : surname.gsub!(/^(.)[^ ]*/, '\1')
            end
          end

          attributes = {
            firstname:     name,
            lastname:      surname,
            mail:          mail,
            last_login_on: Time.now
          }

          user.assign_attributes attributes

          if user.save
            user.update_attribute(:admin, true) if oic_session.admin?
            oic_session.user_id = user.id
            oic_session.save!
            successful_authentication(user)
          else
            flash.now[:warning] ||= l(:error_unable_to_create_user, :name => user.login) + " "
            user.errors.full_messages.each do |error|
              logger.warn "#{l(:error_unable_to_create_user_due_to, :name => user.login, :error => error)}"
              flash.now[:warning] += "#{error}. "
            end
            return invalid_credentials
          end
        else
          user.update_attribute(:admin, true) if oic_session.admin?
          oic_session.user_id = user.id
          oic_session.save!
          successful_authentication(user)
          user.update_last_login_on!
        end # if user.nil?
      end
    end

    def invalid_credentials
      return super unless OicSession.enabled?

      logger.warn l(:error_failed_login_for, :name => params[:username], :ip => request.remote_ip, :time => Time.now.utc)
      flash.now[:error] = (l(:notice_account_invalid_creditentials) + ". " + "<a href='#{signout_path}'>" + l(:try_different_account) + "</a>").html_safe
    end

    def rpiframe
      @oic_session = OicSession.find(session[:oic_session_id])
      render layout: false
    end

    def sha256
      render layout: false
    end

    def authorize_params
      # compatible with both rails 3 and 4
      if params.respond_to?(:permit)
        params.permit(
          :code,
          :id_token,
          :session_state,
        )
      else
        params.select do |k,v|
          [
            'code',
            'id_token',
            'session_state',
          ].include?(k)
        end
      end
    end
  end
end
