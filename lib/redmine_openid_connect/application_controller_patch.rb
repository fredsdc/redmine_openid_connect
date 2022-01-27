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
  end
end
