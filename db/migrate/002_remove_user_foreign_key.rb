class RemoveUserForeignKey < ActiveRecord::Migration[4.2]
  def self.up
    remove_foreign_key :oic_sessions, :user
  end
end
