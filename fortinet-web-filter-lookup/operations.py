""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import get_logger, ConnectorError
import requests
from bs4 import BeautifulSoup
import requests.exceptions as req_exceptions

MACRO_LIST = ["URL_Enrichment_Playbooks_IRIs", "Domain_Enrichment_Playbooks_IRIs"]
CONNECTOR_NAME = "fortinet-web-filter-lookup"
logger = get_logger('fortinet-web-filter-lookup')


class FortiGuard(object):
    def __init__(self, config):
        self.base_url = config.get('base_url') + 'webfilter'
        self.verify_ssl = config.get('verify_ssl')

    def get_response(self, sample_url):
        try:
            url = self.base_url
            use_ssl = self.verify_ssl
            params = {'q': sample_url, 'version': 8}
            req = requests.get(url=url, params=params, verify=use_ssl)
            logger.error('Response: req = {0}'.format(req))
            return req

        except req_exceptions.SSLError:
            logger.error('An SSL error occurred')
            raise ConnectorError('An SSL error occurred')
        except req_exceptions.ConnectionError:
            logger.error('A connection error occurred')
            raise ConnectorError('A connection error occurred')
        except req_exceptions.Timeout:
            logger.error('The request timed out')
            raise ConnectorError('The request timed out')
        except req_exceptions.RequestException:
            logger.error('There was an error while handling the request')
            raise ConnectorError('There was an error while handling the request')
        except Exception as err:
            logger.error(str(err))
            raise ConnectorError('{0}'.format(str(err)))

    def check_response(self, response, sample_url):
        try:
            if response.status_code == 200:
                html_parser = BeautifulSoup(response.text)
                category = html_parser.find('div', {'class': 'well'}).find('h4', {'class': 'info_title'}).text
                info = html_parser.find('div', {'class': 'well'}).find_all('p')[1].text
                return {'url': sample_url, 'category': category.replace('Category: ', ''), 'info': info}
            else:
                raise ConnectorError('ERROR Response Status Code : <{0}>'.format(response.status_code))

        except Exception as err:
            logger.error(str(err))
            raise ConnectorError('{0}'.format(str(err)))

    def site_hc(self, response, base_url):
        try:
            if response.status_code != 200:
                raise ConnectorError('{0} is unavailable. Status Code : <{1}>'.format(base_url, response.status_code))
            else:
                return True

        except Exception as err:
            logger.error(str(err))


def url_review(config, params):
    try:
        logger.info('Initiating URL review operation')
        s = FortiGuard(config)
        sample_url = params.get('sample_url')
        response = s.get_response(sample_url)
        result = s.check_response(response, sample_url)
        return result

    except Exception as err:
        logger.error(str(err))
        raise ConnectorError('{0}'.format(str(err)))


def health_check(config):
    try:
        logger.info('Initiating Connector Health Check')
        s = FortiGuard(config)
        base_url = config.get('base_url')
        response = s.get_response(base_url)
        result = s.site_hc(response, base_url)
        return result

    except Exception as err:
        logger.error(str(err))
        raise ConnectorError('{0}'.format(str(err)))


operations = {
    'url_review': url_review
}
