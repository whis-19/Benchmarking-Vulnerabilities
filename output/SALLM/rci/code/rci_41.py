import logging
    import logging.config
    import yaml

    # Load logging configuration
    try:
        with open('logging.yaml', 'r') as f:
            config = yaml.safe_load(f)
            logging.config.dictConfig(config)
        logger = logging.getLogger(__name__)
    except FileNotFoundError:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        logger = logging.getLogger(__name__)
        logger.warning("logging.yaml not found, using basic logging configuration")

