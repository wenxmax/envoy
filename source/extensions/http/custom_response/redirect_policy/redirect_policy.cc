#include "source/extensions/http/custom_response/redirect_policy/redirect_policy.h"

#include <string>
#include <variant>

#include "envoy/config/route/v3/route_components.pb.h"
#include "envoy/stream_info/filter_state.h"

#include "source/common/common/enum_to_int.h"
#include "source/common/http/header_map_impl.h"
#include "source/common/http/message_impl.h"
#include "source/common/http/utility.h"
#include "source/extensions/filters/http/custom_response/custom_response_filter.h"

namespace {
bool schemeIsHttp(const ::Envoy::Http::RequestHeaderMap& downstream_headers,
                  Envoy::OptRef<const Envoy::Network::Connection> connection) {
  if (downstream_headers.getSchemeValue() == ::Envoy::Http::Headers::get().SchemeValues.Http) {
    return true;
  }
  if (connection.has_value() && !connection->ssl()) {
    return true;
  }
  return false;
}

::Envoy::Http::Utility::RedirectConfig
createRedirectConfig(const envoy::config::route::v3::RedirectAction& redirect_action) {
  ::Envoy::Http::Utility::RedirectConfig redirect_config{
      redirect_action.scheme_redirect(),
      redirect_action.host_redirect(),
      redirect_action.port_redirect() ? ":" + std::to_string(redirect_action.port_redirect()) : "",
      redirect_action.path_redirect(),
      "",      // prefix_rewrite
      "",      // regex_rewrite_redirect_substitution
      nullptr, // regex_rewrite_redirect
      redirect_action.path_redirect().find('?') != absl::string_view::npos,
      redirect_action.https_redirect(),
      redirect_action.strip_query()};
  if (redirect_action.has_regex_rewrite()) {
    throw Envoy::EnvoyException("regex_rewrite is not supported for Custom Response");
  }
  if (redirect_action.has_prefix_rewrite()) {
    throw Envoy::EnvoyException("prefix_rewrite is not supported for Custom Response");
  }
  return redirect_config;
}

} // namespace

namespace Envoy {
namespace Extensions {
namespace Http {
namespace CustomResponse {

RedirectPolicy::RedirectPolicy(
    const envoy::extensions::http::custom_response::redirect_policy::v3::RedirectPolicy& config,
    Stats::StatName stats_prefix, Envoy::Server::Configuration::ServerFactoryContext& context)
    : stat_names_(context.scope().symbolTable()),
      stats_(stat_names_, context.scope(), stats_prefix),
      uri_{config.has_uri() ? std::make_unique<std::string>(config.uri()) : nullptr},
      redirect_action_{config.has_redirect_action()
                           ? std::make_unique<::Envoy::Http::Utility::RedirectConfig>(
                                 createRedirectConfig(config.redirect_action()))
                           : nullptr},
#if defined(HIGRESS)
      uri_from_response_header_{config.has_uri_from_response_header()
                                    ? absl::optional<std::string>(config.uri_from_response_header())
                                    : absl::nullopt},
      use_original_request_uri_(
          PROTOBUF_GET_WRAPPED_OR_DEFAULT(config, use_original_request_uri, false)),
      keep_original_response_code_(
          PROTOBUF_GET_WRAPPED_OR_DEFAULT(config, keep_original_response_code, true)),
      max_internal_redirects_(PROTOBUF_GET_WRAPPED_OR_DEFAULT(config, max_internal_redirects, 1)),
      use_original_request_body_(
          PROTOBUF_GET_WRAPPED_OR_DEFAULT(config, use_original_request_body, false)),
      only_redirect_upstream_code_(
          PROTOBUF_GET_WRAPPED_OR_DEFAULT(config, only_redirect_upstream_code, false)),
#endif
      status_code_{config.has_status_code()
                       ? absl::optional<::Envoy::Http::Code>(
                             static_cast<::Envoy::Http::Code>(config.status_code().value()))
                       : absl::optional<::Envoy::Http::Code>{}},
      response_header_parser_(
          Envoy::Router::HeaderParser::configure(config.response_headers_to_add())),
      request_header_parser_(
          Envoy::Router::HeaderParser::configure(config.request_headers_to_add())),
      modify_request_headers_action_(createModifyRequestHeadersAction(config, context)) {
#if defined(HIGRESS)
  // Ensure that exactly one of uri_ or redirect_action_ or use_original_request_uri_ is specified.
  ASSERT(int(uri_ != nullptr) + int(redirect_action_ != nullptr) + int(use_original_request_uri_) +
             int(uri_from_response_header_.has_value()) ==
         1);
#else
  // Ensure that exactly one of uri_ or redirect_action_ is specified.
  ASSERT((uri_ || redirect_action_) && !(uri_ && redirect_action_));
#endif

  if (uri_) {
    ::Envoy::Http::Utility::Url absolute_url;
    if (!absolute_url.initialize(*uri_, false)) {
      throw EnvoyException(
          absl::StrCat("Invalid uri specified for redirection for custom response: ", *uri_));
    }
  }
  if (redirect_action_ && redirect_action_->path_redirect_.find('#') != std::string::npos) {
    throw EnvoyException(
        absl::StrCat("#fragment is not supported for custom response. Specified path_redirect is ",
                     redirect_action_->path_redirect_));
  }
}

std::unique_ptr<ModifyRequestHeadersAction> RedirectPolicy::createModifyRequestHeadersAction(
    const envoy::extensions::http::custom_response::redirect_policy::v3::RedirectPolicy& config,
    Envoy::Server::Configuration::ServerFactoryContext& context) {
  std::unique_ptr<ModifyRequestHeadersAction> action;
  if (config.has_modify_request_headers_action()) {
    auto& factory = Envoy::Config::Utility::getAndCheckFactory<ModifyRequestHeadersActionFactory>(
        config.modify_request_headers_action());
    const auto action_config = Envoy::Config::Utility::translateAnyToFactoryConfig(
        config.modify_request_headers_action().typed_config(), context.messageValidationVisitor(),
        factory);
    action = factory.createAction(*action_config, config, context);
  }
  return action;
}

::Envoy::Http::FilterHeadersStatus RedirectPolicy::encodeHeaders(
    ::Envoy::Http::ResponseHeaderMap& headers, bool,
    Extensions::HttpFilters::CustomResponse::CustomResponseFilter& custom_response_filter) const {
  // If filter state for custom response exists, it means this response is a
  // custom response. Apply the custom response mutations to the response from
  // the remote source and return.
  auto encoder_callbacks = custom_response_filter.encoderCallbacks();
  auto decoder_callbacks = custom_response_filter.decoderCallbacks();
#if defined(HIGRESS)
  auto* filter_state =
      encoder_callbacks->streamInfo()
          .filterState()
          ->getDataMutable<
              ::Envoy::Extensions::HttpFilters::CustomResponse::CustomResponseFilterState>(
              "envoy.filters.http.custom_response");
  if (filter_state && filter_state->remain_redirect_times-- <= 0) {
    ENVOY_BUG(filter_state->policy.get() == this, "Policy filter state should be this policy.");
    // Only process response on last redirect

    // Apply header mutations.
    response_header_parser_->evaluateHeaders(headers, encoder_callbacks->streamInfo());
    const absl::optional<::Envoy::Http::Code> status_code_to_use =
        status_code_.has_value() ? status_code_
                                 : (filter_state->original_response_code.has_value()
                                        ? filter_state->original_response_code
                                        : absl::nullopt);
    // Modify response status code.
    if (status_code_to_use.has_value()) {
      auto const code = *status_code_to_use;
      headers.setStatus(std::to_string(enumToInt(code)));
      encoder_callbacks->streamInfo().setResponseCode(static_cast<uint32_t>(code));
    }
    return ::Envoy::Http::FilterHeadersStatus::Continue;
  }
  if (only_redirect_upstream_code_) {
    const auto& streamInfo = encoder_callbacks->streamInfo();
    if (!streamInfo.responseCodeDetails().has_value()) {
      return ::Envoy::Http::FilterHeadersStatus::Continue;
    }
    if (streamInfo.responseCodeDetails().value() !=
        ::Envoy::StreamInfo::ResponseCodeDetails::get().ViaUpstream) {
      return ::Envoy::Http::FilterHeadersStatus::Continue;
    }
  }
#else
  const ::Envoy::Extensions::HttpFilters::CustomResponse::CustomResponseFilterState* filter_state =
      encoder_callbacks->streamInfo()
          .filterState()
          ->getDataReadOnly<
              ::Envoy::Extensions::HttpFilters::CustomResponse::CustomResponseFilterState>(
              "envoy.filters.http.custom_response");
  if (filter_state) {
    ENVOY_BUG(filter_state->policy.get() == this, "Policy filter state should be this policy.");
    // Apply header mutations.
    response_header_parser_->evaluateHeaders(headers, encoder_callbacks->streamInfo());
    const absl::optional<::Envoy::Http::Code> status_code_to_use =
        status_code_.has_value() ? status_code_
                                 : (filter_state->original_response_code.has_value()
                                        ? filter_state->original_response_code
                                        : absl::nullopt);
    // Modify response status code.
    if (status_code_to_use.has_value()) {
      auto const code = *status_code_to_use;
      headers.setStatus(std::to_string(enumToInt(code)));
      encoder_callbacks->streamInfo().setResponseCode(static_cast<uint32_t>(code));
    }
    return ::Envoy::Http::FilterHeadersStatus::Continue;
  }
#endif

  auto downstream_headers = custom_response_filter.downstreamHeaders();
  // Modify the request headers & recreate stream.
  if (custom_response_filter.onLocalReplyCalled() && downstream_headers == nullptr) {
    // This condition is true if send local reply is called at any point before
    // the decodeHeaders call for the custom response filter.
    return ::Envoy::Http::FilterHeadersStatus::Continue;
  }
  RELEASE_ASSERT(downstream_headers != nullptr, "downstream_headers cannot be nullptr");

  // Don't change the scheme from the original request
  const bool scheme_is_http = schemeIsHttp(*downstream_headers, decoder_callbacks->connection());

  // Cache original host and path
  const std::string original_host(downstream_headers->getHostValue());
  const std::string original_path(downstream_headers->getPathValue());
  const bool scheme_is_set = (downstream_headers->Scheme() != nullptr);
  // Replace the original host, scheme and path.
  Cleanup restore_original_headers(
      [original_host, original_path, scheme_is_set, scheme_is_http, downstream_headers]() {
        downstream_headers->setHost(original_host);
        downstream_headers->setPath(original_path);
        if (scheme_is_set) {
          downstream_headers->setScheme(scheme_is_http
                                            ? ::Envoy::Http::Headers::get().SchemeValues.Http
                                            : ::Envoy::Http::Headers::get().SchemeValues.Https);
        }
      });

  ::Envoy::Http::Utility::Url absolute_url;
#if defined(HIGRESS)
  if (use_original_request_uri_) {
    std::string real_original_host;
    const auto x_envoy_original_host = downstream_headers->getByKey(
        ::Envoy::Http::CustomHeaders::get().AliExtendedValues.XEnvoyOriginalHost);
    if (x_envoy_original_host && !(*x_envoy_original_host).empty()) {
      real_original_host = *x_envoy_original_host;
    } else {
      real_original_host = original_host;
    }
    std::string real_original_path(downstream_headers->getEnvoyOriginalPathValue().empty()
                                       ? original_path
                                       : downstream_headers->getEnvoyOriginalPathValue());
    downstream_headers->setHost(real_original_host);
    downstream_headers->setPath(real_original_path);
  } else {
    std::string uri;
    if (uri_from_response_header_.has_value()) {
      auto custom_location = headers.get(Envoy::Http::LowerCaseString(*uri_from_response_header_));
      uri = custom_location.empty() ? "" : custom_location[0]->value().getStringView();
      if (uri == "" || !absolute_url.initialize(uri, false)) {
        stats_.custom_response_invalid_uri_.inc();
        ENVOY_LOG(debug, "uri specified in response header is invalid");
        return ::Envoy::Http::FilterHeadersStatus::Continue;
      }
    } else {
      uri = uri_ ? *uri_ : ::Envoy::Http::Utility::newUri(*redirect_action_, *downstream_headers);
#else
  std::string uri(uri_ ? *uri_
                       : ::Envoy::Http::Utility::newUri(*redirect_action_, *downstream_headers));
#endif

      if (!absolute_url.initialize(uri, false)) {
        stats_.custom_response_invalid_uri_.inc();
        // We could potentially get an invalid url only if redirect_action_ was specified instead
        // of uri_. Hence, assert that uri_ is not set.
        ENVOY_BUG(!static_cast<bool>(uri_),
                  "uri should not be invalid as this was already validated during config load");
        return ::Envoy::Http::FilterHeadersStatus::Continue;
      }
#if defined(HIGRESS)
    }
#endif
    downstream_headers->setScheme(absolute_url.scheme());
    downstream_headers->setHost(absolute_url.hostAndPort());

    auto path_and_query = absolute_url.pathAndQueryParams();
    // Strip the #fragment from Location URI if it is present. Envoy treats
    // internal redirect as a new request and will reject it if the URI path
    // contains #fragment.
    const auto fragment_pos = path_and_query.find('#');
    path_and_query = path_and_query.substr(0, fragment_pos);

    downstream_headers->setPath(path_and_query);
#if defined(HIGRESS)
  }
  auto original_upstream_cluster = encoder_callbacks->streamInfo().upstreamClusterInfo();
#endif
  if (decoder_callbacks->downstreamCallbacks()) {
    decoder_callbacks->downstreamCallbacks()->clearRouteCache();
  }
  // Apply header mutations before recalculating the route.
  request_header_parser_->evaluateHeaders(*downstream_headers, decoder_callbacks->streamInfo());
  if (modify_request_headers_action_) {
    modify_request_headers_action_->modifyRequestHeaders(*downstream_headers, headers,
                                                         decoder_callbacks->streamInfo(), *this);
  }
  const auto route = decoder_callbacks->route();
  // Don't allow a redirect to a non existing route.
  if (!route) {
    stats_.custom_response_redirect_no_route_.inc();
    ENVOY_LOG(trace, "Redirect for custom response failed: no route found");
    // Note that at this point the header mutations have already taken into affect
    // and access logs will log the mutated headers, even though no internal
    // redirect will take place.
    return ::Envoy::Http::FilterHeadersStatus::Continue;
  }
#if !defined(HIGRESS)
  downstream_headers->setMethod(::Envoy::Http::Headers::get().MethodValues.Get);
#endif
  downstream_headers->remove(::Envoy::Http::Headers::get().ContentLength);
  // Cache the original response code.
  absl::optional<::Envoy::Http::Code> original_response_code;
#if defined(HIGRESS)
  if (original_upstream_cluster.has_value()) {
    encoder_callbacks->streamInfo().setUpstreamClusterInfo(*original_upstream_cluster);
  }
  absl::optional<uint64_t> current_code =
      ::Envoy::Http::Utility::getResponseStatusOrNullopt(headers);
  if (current_code.has_value()) {
    encoder_callbacks->streamInfo().setResponseCode(static_cast<uint32_t>(*current_code));
  }
  if (keep_original_response_code_) {
    if (current_code.has_value()) {
      original_response_code = static_cast<::Envoy::Http::Code>(*current_code);
    }
  }
  if (!filter_state) {
    encoder_callbacks->streamInfo().filterState()->setData(
        // TODO(pradeepcrao): Currently we don't have a mechanism to add readonly
        // objects to FilterState, even if they're immutable.
        "envoy.filters.http.custom_response",
        std::make_shared<
            ::Envoy::Extensions::HttpFilters::CustomResponse::CustomResponseFilterState>(
            this->shared_from_this(), original_response_code, max_internal_redirects_ - 1),
        StreamInfo::FilterState::StateType::Mutable, StreamInfo::FilterState::LifeSpan::Request);
  } else {
    filter_state->policy = this->shared_from_this();
  }
  restore_original_headers.cancel();
  // Should not return StopIteration if recreateStream failed
  return decoder_callbacks->recreateStream(nullptr, use_original_request_body_)
             ? ::Envoy::Http::FilterHeadersStatus::StopIteration
             : ::Envoy::Http::FilterHeadersStatus::Continue;
#else
  absl::optional<uint64_t> current_code =
      ::Envoy::Http::Utility::getResponseStatusOrNullopt(headers);
  if (current_code.has_value()) {
    original_response_code = static_cast<::Envoy::Http::Code>(*current_code);
  }
  encoder_callbacks->streamInfo().filterState()->setData(
      // TODO(pradeepcrao): Currently we don't have a mechanism to add readonly
      // objects to FilterState, even if they're immutable.
      "envoy.filters.http.custom_response",
      std::make_shared<::Envoy::Extensions::HttpFilters::CustomResponse::CustomResponseFilterState>(
          const_cast<RedirectPolicy*>(this)->shared_from_this(), original_response_code,
          max_internal_redirects_),
      StreamInfo::FilterState::StateType::ReadOnly, StreamInfo::FilterState::LifeSpan::Request);
  restore_original_headers.cancel();
  decoder_callbacks->recreateStream(nullptr);
#endif

  return ::Envoy::Http::FilterHeadersStatus::StopIteration;
}

} // namespace CustomResponse
} // namespace Http
} // namespace Extensions
} // namespace Envoy
