config = {

    # This config file will be detected in localhost environment and values defined here will overwrite those in config.py
    'environment': "localhost",

    # ----> ADD MORE CONFIGURATION OPTIONS HERE <----
    'captcha_public_key': "6Ldi0u4SAAAAAC8pjDop1aDdmeiVrUOU2M4i23tT",
    'captcha_private_key': "6Ldi0u4SAAAAAPzk1gaFDRQgry7XW4VBvNCqCHuJ",
    
       # application name
    'app_name': "Alf4Gae Example",

    # the default language code for the application.
    # should match whatever language the site uses when i18n is disabled
    'app_lang': 'en',

    # Locale code = <language>_<territory> (ie 'en_US')
    # to pick locale codes see http://cldr.unicode.org/index/cldr-spec/picking-the-right-language-code
    # also see http://www.sil.org/iso639-3/codes.asp
    # Language codes defined under iso 639-1 http://en.wikipedia.org/wiki/List_of_ISO_639-1_codes
    # Territory codes defined under iso 3166-1 alpha-2 http://en.wikipedia.org/wiki/ISO_3166-1
    # disable i18n if locales array is empty or None
    'locales': [],
    
    # Disable local accounts
    
    'disable_local_accounts': True,
    
    
    # get your own client key and client  secret by registering at https://developers.alfresco.com
    'alfresco_server': 'alfresco.com',
    'alfresco_redirect_uri': 'http://localhost:8080/social_login/alfresco/complete',
    # The alfresco key & secret
    'alfresco_client_id': 'l7xxa7b070d8177b4ed08dcedb756e933fd2',
    'alfresco_client_secret': 'ae5c1aa4b1fc4848a5ffa5d80823a3b3',
    # The alfresco Network
    'alfresco_network': 'alfresco.com'

}