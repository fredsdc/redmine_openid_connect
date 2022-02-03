module RedmineOpenidConnect
  module ApplicationControllerPatch
    def session_expiration
      unless params[:action].match?(/^oic_/)
        super
      end
    end

    # set the current user _without_ resetting the oic_session_id
    def logged_user=(user)
      oic_session_id=session[:oic_session_id]
      super(user)
      session[:oic_session_id] = oic_session_id
    end

    def find_current_user
      if api_request? && Setting.rest_api_enabled? && accept_api_auth? && !api_key_from_request.present? && session[:user_id]
        params[:key] = User.active.find(session[:user_id]).api_key rescue nil
      end
      user = super
    end
  end
end
