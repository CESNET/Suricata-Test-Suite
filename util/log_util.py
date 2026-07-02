import logging
import sys
from pathlib import Path


PROGRESS_LEVEL = 21
logging.addLevelName(PROGRESS_LEVEL, "PROGRESS")


def _logger_progress(self, msg, *args, **kwargs):
    if self.isEnabledFor(PROGRESS_LEVEL):
        self._log(PROGRESS_LEVEL, msg, args, **kwargs)


logging.Logger.progress = _logger_progress
logging.PROGRESS = PROGRESS_LEVEL


FILE_LOG_FORMAT = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
CONSOLE_LOG_FORMAT = "%(level_type)s | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
_SUITE_HANDLER_ATTR = "_suricata_suite_handler"
_NOISY_LOGGERS = ("invoke", "fabric", "paramiko", "faker")


class ColoredTypeFormatter(logging.Formatter):
    """Format console logs as [TYPE] | message with colored TYPE."""

    _RESET = "\033[0m"
    _COLORS = {
        logging.DEBUG: "\033[36m",  # cyan
        logging.INFO: "\033[32m",  # green
        logging.PROGRESS: "\033[34m",  # blue
        logging.WARNING: "\033[33m",  # yellow
        logging.ERROR: "\033[31m",  # red
        logging.CRITICAL: "\033[35m",  # magenta
    }

    def format(self, record: logging.LogRecord) -> str:
        level_type = f"[{record.levelname}]"
        color = self._COLORS.get(record.levelno)
        if color:
            level_type = f"{color}{level_type}{self._RESET}"

        record.level_type = level_type
        return super().format(record)


def _to_level(level: str | int) -> int:
    if isinstance(level, int):
        return level

    resolved = logging.getLevelName(str(level).upper())
    if isinstance(resolved, int):
        return resolved
    return logging.INFO


def _remove_suite_handlers(logger: logging.Logger) -> None:
    for handler in list(logger.handlers):
        if getattr(handler, _SUITE_HANDLER_ATTR, False):
            logger.removeHandler(handler)
            handler.close()


def _reset_root_handlers(logger: logging.Logger) -> None:
    """Remove handlers created by this module to prevent duplicate emissions."""
    for handler in list(logger.handlers):
        if getattr(handler, _SUITE_HANDLER_ATTR, False):
            logger.removeHandler(handler)
            handler.close()


def _normalize_library_loggers() -> None:
    """Avoid duplicate output from libraries that attach their own stream handlers."""
    for logger_name in _NOISY_LOGGERS:
        lib_logger = logging.getLogger(logger_name)
        for handler in list(lib_logger.handlers):
            if isinstance(handler, logging.StreamHandler):
                lib_logger.removeHandler(handler)
        lib_logger.propagate = False


def setup_logging(level: str | int = "INFO", log_file: str | None = None) -> None:
    """
    Configure root logging for the test suite.

    Setup is idempotent and only replaces handlers previously created by this module.
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)
        handler.close()
    
    _normalize_library_loggers()

    console_formatter = ColoredTypeFormatter(fmt=CONSOLE_LOG_FORMAT)
    file_formatter = logging.Formatter(fmt=FILE_LOG_FORMAT, datefmt=DATE_FORMAT)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(_to_level(level))
    stream_handler.setFormatter(console_formatter)
    setattr(stream_handler, _SUITE_HANDLER_ATTR, True)
    root_logger.addHandler(stream_handler)

    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_path)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(file_formatter)
        setattr(file_handler, _SUITE_HANDLER_ATTR, True)
        root_logger.addHandler(file_handler)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
