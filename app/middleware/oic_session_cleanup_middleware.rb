class OicSessionCleanupMiddleware
  CHECK_RATIO = [ENV.fetch('OIC_SESSION_CLEANUP_CHECK_RATIO', '100').to_i, 1].max

  def initialize(app)
    @app = app
    @request_count = 0
    @counter_mutex = Mutex.new
  end

  def call(env)
    run_cleanup_if_due
    @app.call(env)
  end

  private

  def run_cleanup_if_due
    should_check = @counter_mutex.synchronize do
      @request_count += 1
      if @request_count >= CHECK_RATIO
        @request_count = 0
        true
      else
        false
      end
    end

    OicSessionCleanupService.run_if_due if should_check
  end
end
