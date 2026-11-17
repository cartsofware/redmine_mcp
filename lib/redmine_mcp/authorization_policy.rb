# frozen_string_literal: true

# Redmine MCP plugin
# Additional OAuth2 authentication support: CART contributors
# SPDX-License-Identifier: GPL-2.0-or-later

module RedmineMcp
  class AuthorizationPolicy
    def self.authorize!(user)
      raise Auth::Unauthorized unless user&.active?

      unless user.allowed_to?(:use_mcp, nil, global: true)
        Logger.warn("permission denied for MCP access, user=#{user.login}")
        raise Auth::Forbidden, I18n.t(:error_mcp_access_denied)
      end

      user
    end
  end
end
