"""Network diagnostics cannot log signed download URLs or transport exceptions."""

import logging


class NetworkMetadataOnly(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg, record.args = "network_http_request", ()
        record.exc_info, record.exc_text, record.stack_info = None, None, None
        return True


def protect_network_logs() -> None:
    logger = logging.getLogger("httpx")
    if not any(isinstance(item, NetworkMetadataOnly) for item in logger.filters):
        logger.addFilter(NetworkMetadataOnly())
    logging.getLogger("httpcore").setLevel(logging.WARNING)
