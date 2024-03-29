require 'redmine'
require 'redmine_openid_connect/application_controller_patch'
require 'redmine_openid_connect/account_controller_patch'
require 'redmine_openid_connect/hooks'

Redmine::Plugin.register :redmine_openid_connect do
  name 'Redmine Openid Connect plugin'
  author 'Alfonso Juan Dillera / Markus M. May / Frederico Camara'
  description 'Serpro OpenID Connect implementation for Redmine'
  version '0.10.0'
  url 'https://github.com/fredsdc/redmine_openid_connect'
  author_url 'http://github.com/adillera'

  settings :default => { 'empty' => true }, partial: 'settings/redmine_openid_connect_settings'
end

Rails.configuration.to_prepare do
  ApplicationController.prepend(RedmineOpenidConnect::ApplicationControllerPatch)
  AccountController.prepend(RedmineOpenidConnect::AccountControllerPatch)
end
