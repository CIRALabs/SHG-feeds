$ADMININTERFACE ||= ENV['ADMININTERFACE']

Rails.application.routes.draw do
  resources :administrators
  resources :devices

  # EST processing at well known URLs
  post '/.well-known/est/requestvoucher', to: 'est#requestvoucher'
  post '/.well-known/est/voucher_status', to: 'est#voucher_status'
  get  '/.well-known/est/cacerts',        to: 'est#cacerts'
  get  '/.well-known/est/csrattributes',  to: 'est#csrattributes'
  post '/.well-known/est/simpleenroll',   to: 'est#simpleenroll'
  post '/.well-known/est/requestvoucherrequest', to: 'smarkaklink#rvr'
  post '/.well-known/est/voucher',        to: 'smarkaklink#voucher'

  post '/jwt',        to: 'secure_gateway#login_jwt'

  if true # was $COAPSERVER, but it does not get set early enough.
    #get '/.well-known/core',   to: 'core#index'
    post '/e/rv', to: 'est#cbor_rv', coap: true, rt: 'ace.est', short: '/e'
    post '/e/vs', to: 'est#cbor_vs', coap: true, rt: 'ace.est', short: '/e'

    # get /cacerts
    get '/e/crts', to: 'est#cbor_crts', coap: true, rt: 'ace.est', short: '/e'

    # get /att
    get  '/.well-known/est/att', to: 'est#cbor_crts', coap: true, rt: 'ace.est', short: '/e'
    get '/e/att',  to: 'est#cbor_crts', coap: true, rt: 'ace.est', short: '/e'

    # get /sen -- simpleenroll
    get  '/.well-known/est/sen', to: 'est#simpleenroll', coap: true, rt: 'ace.est', short: '/e'
    get '/e/sen',                to: 'est#simpleenroll', coap: true, rt: 'ace.est', short: '/e'
  end

  resources :status,  :only => [:index ]
  resources :version, :only => [:index ]

end
