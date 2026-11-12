class OicSessionCleanupService
  CHECK_INTERVAL = 1.day
  RUN_MUTEX = Mutex.new

  class << self
    def run_if_due
      RUN_MUTEX.synchronize do
        return 0 unless due?

        deleted_count = OicSession.where('expires_at < ?', Time.current).delete_all
        @last_run_at = Time.current

        Rails.logger.info("[OIC] Deleted #{deleted_count} expired sessions")
        deleted_count
      end
    rescue StandardError => error
      Rails.logger.error("[OIC] Session cleanup failed: #{error.message}")
      0
    end

    private

    def due?
      @last_run_at.nil? || @last_run_at <= CHECK_INTERVAL.ago
    end
  end
end
