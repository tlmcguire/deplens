
def disable_librelogo_event_handlers():

    libreoffice_document = get_current_document()

    libreoffice_document.disable_event_handler("onMouseOver")
    libreoffice_document.disable_event_handler("onDocumentOpen")
    libreoffice_document.disable_event_handler("onDocumentClose")

    print("LibreLogo event handlers disabled to prevent arbitrary code execution.")

disable_librelogo_event_handlers()