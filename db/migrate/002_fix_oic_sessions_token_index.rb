class FixOicSessionsTokenIndex < ActiveRecord::Migration[4.2]
  def self.up
    # Add hash columns for tokens that are too large to index
    add_column :oic_sessions, :access_token_hash, :string unless column_exists?(:oic_sessions, :access_token_hash)
    add_column :oic_sessions, :refresh_token_hash, :string unless column_exists?(:oic_sessions, :refresh_token_hash)

    # Hash existing tokens
    say "Hashing existing tokens..."
    execute "UPDATE oic_sessions SET access_token_hash = md5(access_token) WHERE access_token IS NOT NULL AND access_token_hash IS NULL"
    execute "UPDATE oic_sessions SET refresh_token_hash = md5(refresh_token) WHERE refresh_token IS NOT NULL AND refresh_token_hash IS NULL"

    # Remove old problematic indexes
    remove_index :oic_sessions, :access_token if index_exists?(:oic_sessions, :access_token)
    remove_index :oic_sessions, :refresh_token if index_exists?(:oic_sessions, :refresh_token)

    # Add new indexes on hash columns
    add_index :oic_sessions, :access_token_hash, unique: true
    add_index :oic_sessions, :refresh_token_hash, unique: true
  end

  def self.down
    # Remove hash columns and indexes
    remove_index :oic_sessions, :access_token_hash if index_exists?(:oic_sessions, :access_token_hash)
    remove_index :oic_sessions, :refresh_token_hash if index_exists?(:oic_sessions, :refresh_token_hash)
    remove_column :oic_sessions, :access_token_hash if column_exists?(:oic_sessions, :access_token_hash)
    remove_column :oic_sessions, :refresh_token_hash if column_exists?(:oic_sessions, :refresh_token_hash)

    # Restore old indexes (if needed)
    add_index :oic_sessions, :access_token unless index_exists?(:oic_sessions, :access_token)
    add_index :oic_sessions, :refresh_token unless index_exists?(:oic_sessions, :refresh_token)
  end
end
