# Copyright (C) 2020 Extreme Networks, Inc - All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import

import json
import mock
import time
import calendar
import saml2

import requests

from oslo_config import cfg
from six.moves import http_client

import st2auth
from st2auth import sso as st2auth_sso
from st2auth import app
from st2auth_sso_saml2 import saml
from st2common.exceptions import auth as auth_exc
from st2tests import config
from st2tests import DbTestCase
from st2tests.api import TestApp
from st2common.services.access import create_web_sso_request


SSO_V1_PATH = '/v1/sso'
SSO_REQUEST_V1_PATH = SSO_V1_PATH + '/request/web'
SSO_CALLBACK_V1_PATH = SSO_V1_PATH + '/callback'

MOCK_ENTITY_ID = 'http://localhost'
MOCK_ACS_URL = '%s/auth/sso/callback' % MOCK_ENTITY_ID
# We need this format for the certs to work
MOCK_IDP_URL = 'http://keycloak:8080/realms/stackstorm'
MOCK_METADATA_URL = '%s/saml/metadata' % MOCK_IDP_URL
MOCK_REDIRECT_URL = '%s/app/st2/sso/saml' % MOCK_IDP_URL
MOCK_X509_KEYNAME = 'ItvZoblEFKfq1reEoL1QJL5qra8rrhMq107KbkflBs4'
MOCK_X509_CERT = (
    'MIICozCCAYsCBgF/vGdbojANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDDApzdGFja3N0b3JtMB4XDTIy'
    'MDMyNDE0NDc0NFoXDTMyMDMyNDE0NDkyNFowFTETMBEGA1UEAwwKc3RhY2tzdG9ybTCCASIwDQYJKoZI'
    'hvcNAQEBBQADggEPADCCAQoCggEBAO8MYo0xHZjsVXHtn0H7Cow/+VF1SQZd0Yri4LfXlpee+uRb93mO'
    'pk8p1Tj1ZDYz38PFZgcAN4Pd5+xcMcPf5FYf7zi6f0hyOfew1EC9VW3BFGz8SpFx0A+LOinQUxoWMZVE'
    'MdPUFPUa3hE80Ww/RvUAp05TwbGODku08GxmhspVTIGlnAF0VvbKA1NYnRpfGFxx2xCh9IlIqqmXyu96'
    'MU8cgiAgvdNPDOL/3WjqEkAWSfafJWs7/hukbNDl5DsBXRvjW/03oSREE1CW+G4fjOx+os0rUO4sgY7o'
    'kN7dgurtk8BZQOJI8i3zmmWEm8g//zcrJRvbbmdbNc70E3Zu+BUCAwEAATANBgkqhkiG9w0BAQsFAAOC'
    'AQEA0EXirrmgmpL67vfzbKVyoQ9faXfzk/QrGG+ZlIrni/+QmCuR0Qc4weh65P2iv/oCHndMzIwMEPGa'
    'sfP6VG6yULd1YQzmkIQ6qCxfDmNbhILYLoBa95IxZekqacgZXoLRNiDwyzany46rXRs/mXyYjPwlXynO'
    'Gy/otUmv6qqp0IhoyBM6R4sTFZ5RryfDXx7F3nu8nfKi7LfJxcPBtrCF4Sg//e6JgHjnQyemA4HAOXPi'
    'SXTn2ghKTR/xo5MEVonn296Z3bjYGJuL7mxR+rBdvjW7ZmBGCU6A1g1BlkbjOmlxqFhCSxAtarDSxm3F'
    'd+p1VwylSk+LHg9tnbUL3sBIvg=='
)
MOCK_REFERER = MOCK_ENTITY_ID

MOCK_SAML_RESPONSE_REQUEST_ID = "id_38c65e6f-124c-451f-8ff8-407e1799818e"
MOCK_SAML_RESPONSE = (
    'PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJv'
    'dG9jb2wiIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iIERl'
    'c3RpbmF0aW9uPSJodHRwOi8vbG9jYWxob3N0L2F1dGgvc3NvL2NhbGxiYWNrIiBJRD0iSURfZTg4MjQ0'
    'MjEtOGUyOS00YTc1LTlhODUtNThhNjUyNzI0NTRkIiBJblJlc3BvbnNlVG89ImlkXzM4YzY1ZTZmLTEy'
    'NGMtNDUxZi04ZmY4LTQwN2UxNzk5ODE4ZSIgSXNzdWVJbnN0YW50PSIyMDIyLTA3LTEyVDE3OjM4OjQ1'
    'LjkzN1oiIFZlcnNpb249IjIuMCI+PHNhbWw6SXNzdWVyPmh0dHA6Ly9rZXljbG9hazo4MDgwL3JlYWxt'
    'cy9zdGFja3N0b3JtPC9zYW1sOklzc3Vlcj48ZHNpZzpTaWduYXR1cmUgeG1sbnM6ZHNpZz0iaHR0cDov'
    'L3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+PGRzaWc6U2lnbmVkSW5mbz48ZHNpZzpDYW5vbmlj'
    'YWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhj'
    'LWMxNG4jIi8+PGRzaWc6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcv'
    'MjAwMS8wNC94bWxkc2lnLW1vcmUjcnNhLXNoYTI1NiIvPjxkc2lnOlJlZmVyZW5jZSBVUkk9IiNJRF9l'
    'ODgyNDQyMS04ZTI5LTRhNzUtOWE4NS01OGE2NTI3MjQ1NGQiPjxkc2lnOlRyYW5zZm9ybXM+PGRzaWc6'
    'VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVs'
    'b3BlZC1zaWduYXR1cmUiLz48ZHNpZzpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9y'
    'Zy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L2RzaWc6VHJhbnNmb3Jtcz48ZHNpZzpEaWdlc3RNZXRo'
    'b2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiLz48ZHNp'
    'ZzpEaWdlc3RWYWx1ZT5DTmpGWTZndkFSdWVXQVJPRk82NmVhRXZpd2tlNXFuRHFaKzF3U2hNcEx3PTwv'
    'ZHNpZzpEaWdlc3RWYWx1ZT48L2RzaWc6UmVmZXJlbmNlPjwvZHNpZzpTaWduZWRJbmZvPjxkc2lnOlNp'
    'Z25hdHVyZVZhbHVlPkZ6WXMxUFJNK2w4QzJqYlBFOXluTHA5d0Jla0NMVGZtNzF0MkpydURsSmJiWkh5'
    'TDh6blA4c3kvVURCV1RzYW9sWkxySUlyS2w1cmJwVXZod1ZhbEtlbnBoeXdOeVY0Wm9XSnYyWUljak40'
    'NVkzRTRweXB1QWpLOTN0MUFNT1J2ODB4UmEzc3RmU0R3ZnZBMGlPZTNPb1FqaHFrdWxrVFNwTFEvMUx5'
    'aW1lRG9HRWhpcmVKb2NnTGRaMDJWdXhndmlobmE3MnJpTllZam5IVVdIRldyL1ZWQmhBMlR5RU9yQkFz'
    'emNQV1N2UDhaQnFxYzZHYVNINUI1NWtKNlZPNVhTUE5VektoWmRtZVNwZ0piU05CVEVqZ0lzSzNtdFhO'
    'dG9Zck9jU3hJaXhsYWpHZmwyTXFVdlNxc3hweUc5QU1xVGRjOCtZcUVKK3ZWYnd1SUMwdENNZz09PC9k'
    'c2lnOlNpZ25hdHVyZVZhbHVlPjxkc2lnOktleUluZm8+PGRzaWc6S2V5TmFtZT5JdHZab2JsRUZLZnEx'
    'cmVFb0wxUUpMNXFyYThycmhNcTEwN0tia2ZsQnM0PC9kc2lnOktleU5hbWU+PGRzaWc6WDUwOURhdGE+'
    'PGRzaWc6WDUwOUNlcnRpZmljYXRlPk1JSUNvekNDQVlzQ0JnRi92R2Rib2pBTkJna3Foa2lHOXcwQkFR'
    'c0ZBREFWTVJNd0VRWURWUVFEREFwemRHRmphM04wYjNKdE1CNFhEVEl5TURNeU5ERTBORGMwTkZvWERU'
    'TXlNRE15TkRFME5Ea3lORm93RlRFVE1CRUdBMVVFQXd3S2MzUmhZMnR6ZEc5eWJUQ0NBU0l3RFFZSktv'
    'WklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCQU84TVlvMHhIWmpzVlhIdG4wSDdDb3cvK1ZGMVNR'
    'WmQwWXJpNExmWGxwZWUrdVJiOTNtT3BrOHAxVGoxWkRZejM4UEZaZ2NBTjRQZDUreGNNY1BmNUZZZjd6'
    'aTZmMGh5T2ZldzFFQzlWVzNCRkd6OFNwRngwQStMT2luUVV4b1dNWlZFTWRQVUZQVWEzaEU4MFd3L1J2'
    'VUFwMDVUd2JHT0RrdTA4R3htaHNwVlRJR2xuQUYwVnZiS0ExTlluUnBmR0Z4eDJ4Q2g5SWxJcXFtWHl1'
    'OTZNVThjZ2lBZ3ZkTlBET0wvM1dqcUVrQVdTZmFmSldzNy9odWtiTkRsNURzQlhSdmpXLzAzb1NSRUUx'
    'Q1crRzRmak94K29zMHJVTzRzZ1k3b2tON2RndXJ0azhCWlFPSkk4aTN6bW1XRW04Zy8vemNySlJ2YmJt'
    'ZGJOYzcwRTNadStCVUNBd0VBQVRBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQTBFWGlycm1nbXBMNjd2'
    'ZnpiS1Z5b1E5ZmFYZnprL1FyR0crWmxJcm5pLytRbUN1UjBRYzR3ZWg2NVAyaXYvb0NIbmRNekl3TUVQ'
    'R2FzZlA2Vkc2eVVMZDFZUXpta0lRNnFDeGZEbU5iaElMWUxvQmE5NUl4WmVrcWFjZ1pYb0xSTmlEd3l6'
    'YW55NDZyWFJzL21YeVlqUHdsWHluT0d5L290VW12NnFxcDBJaG95Qk02UjRzVEZaNVJyeWZEWHg3RjNu'
    'dThuZktpN0xmSnhjUEJ0ckNGNFNnLy9lNkpnSGpuUXllbUE0SEFPWFBpU1hUbjJnaEtUUi94bzVNRVZv'
    'bm4yOTZaM2JqWUdKdUw3bXhSK3JCZHZqVzdabUJHQ1U2QTFnMUJsa2JqT21seHFGaENTeEF0YXJEU3ht'
    'M0ZkK3AxVnd5bFNrK0xIZzl0bmJVTDNzQkl2Zz09PC9kc2lnOlg1MDlDZXJ0aWZpY2F0ZT48L2RzaWc6'
    'WDUwOURhdGE+PGRzaWc6S2V5VmFsdWU+PGRzaWc6UlNBS2V5VmFsdWU+PGRzaWc6TW9kdWx1cz43d3hp'
    'alRFZG1PeFZjZTJmUWZzS2pELzVVWFZKQmwzUml1TGd0OWVXbDU3NjVGdjNlWTZtVHluVk9QVmtOalBm'
    'dzhWbUJ3QTNnOTNuN0Z3eHc5L2tWaC92T0xwL1NISTU5N0RVUUwxVmJjRVViUHhLa1hIUUQ0czZLZEJU'
    'R2hZeGxVUXgwOVFVOVJyZUVUelJiRDlHOVFDblRsUEJzWTRPUzdUd2JHYUd5bFZNZ2FXY0FYUlc5c29E'
    'VTFpZEdsOFlYSEhiRUtIMGlVaXFxWmZLNzNveFR4eUNJQ0M5MDA4TTR2L2RhT29TUUJaSjlwOGxhenYr'
    'RzZSczBPWGtPd0ZkRytOYi9UZWhKRVFUVUpiNGJoK003SDZpelN0UTdpeUJqdWlRM3QyQzZ1MlR3RmxB'
    'NGtqeUxmT2FaWVNieUQvL055c2xHOXR1WjFzMXp2UVRkbTc0RlE9PTwvZHNpZzpNb2R1bHVzPjxkc2ln'
    'OkV4cG9uZW50PkFRQUI8L2RzaWc6RXhwb25lbnQ+PC9kc2lnOlJTQUtleVZhbHVlPjwvZHNpZzpLZXlW'
    'YWx1ZT48L2RzaWc6S2V5SW5mbz48L2RzaWc6U2lnbmF0dXJlPjxzYW1scDpTdGF0dXM+PHNhbWxwOlN0'
    'YXR1c0NvZGUgVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2VzcyIv'
    'Pjwvc2FtbHA6U3RhdHVzPjxzYW1sOkFzc2VydGlvbiB4bWxucz0idXJuOm9hc2lzOm5hbWVzOnRjOlNB'
    'TUw6Mi4wOmFzc2VydGlvbiIgSUQ9IklEXzIzNzdjNDQ0LTcwZmUtNDYzNS1hY2RlLTc2YThjZDE1YWJj'
    'YiIgSXNzdWVJbnN0YW50PSIyMDIyLTA3LTEyVDE3OjM4OjQ1LjkzNFoiIFZlcnNpb249IjIuMCI+PHNh'
    'bWw6SXNzdWVyPmh0dHA6Ly9rZXljbG9hazo4MDgwL3JlYWxtcy9zdGFja3N0b3JtPC9zYW1sOklzc3Vl'
    'cj48ZHNpZzpTaWduYXR1cmUgeG1sbnM6ZHNpZz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxk'
    'c2lnIyI+PGRzaWc6U2lnbmVkSW5mbz48ZHNpZzpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRo'
    'bT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PGRzaWc6U2lnbmF0dXJl'
    'TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxkc2lnLW1vcmUjcnNh'
    'LXNoYTI1NiIvPjxkc2lnOlJlZmVyZW5jZSBVUkk9IiNJRF8yMzc3YzQ0NC03MGZlLTQ2MzUtYWNkZS03'
    'NmE4Y2QxNWFiY2IiPjxkc2lnOlRyYW5zZm9ybXM+PGRzaWc6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0'
    'cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz48ZHNpZzpU'
    'cmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMi'
    'Lz48L2RzaWc6VHJhbnNmb3Jtcz48ZHNpZzpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3'
    'LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiLz48ZHNpZzpEaWdlc3RWYWx1ZT5wK2VndzErNVJB'
    'OVJIeFgrb01XbytDZ0s2RkwxQ2lQeWNhOHg5dTE2aFhVPTwvZHNpZzpEaWdlc3RWYWx1ZT48L2RzaWc6'
    'UmVmZXJlbmNlPjwvZHNpZzpTaWduZWRJbmZvPjxkc2lnOlNpZ25hdHVyZVZhbHVlPlR3eldNdjRsS3Ri'
    'KzN3VTMxaWxqNUZORUdudW9lSDZnNG1lY3hiTnJTNXNZY0JhRFo2eVdISGw0WmdpbE5JMk9JbnNzMlBs'
    'WlM0cEdjdXV5T2YvWWQ5SEYrOGFFQ2FaWGtHcExsOXpzZEs3U3hjenNHN3A5Q2ZHZjBtUCtmaitlZGd4'
    'TkZQYVRpcG5GdUdUc05LZVBMdWdxWlNnV0lrSXg5WnFWZ1BhNTdsd2hYd0VzRXoyUTdCZXFHTDdUK3E2'
    'WW9lNjd3M01neDloZW8yK3VKNStydjhQdlc3WGhDdnBsUW9NVjZFZ2NWb21WYkNSZ0pCMWxtVlBYU2xT'
    'aDBta0QyNFNXa2krcDBpYjhuMktkREJOL2pzSGtjamJEbEhQNVFNM21mUGFDWXAxQUN6aFM5SWl2eXlW'
    'cUdUQTFkUktoOEZhaVNoNmVtRTJLQUM4QmU4ZjZ1dz09PC9kc2lnOlNpZ25hdHVyZVZhbHVlPjxkc2ln'
    'OktleUluZm8+PGRzaWc6S2V5TmFtZT5JdHZab2JsRUZLZnExcmVFb0wxUUpMNXFyYThycmhNcTEwN0ti'
    'a2ZsQnM0PC9kc2lnOktleU5hbWU+PGRzaWc6WDUwOURhdGE+PGRzaWc6WDUwOUNlcnRpZmljYXRlPk1J'
    'SUNvekNDQVlzQ0JnRi92R2Rib2pBTkJna3Foa2lHOXcwQkFRc0ZBREFWTVJNd0VRWURWUVFEREFwemRH'
    'RmphM04wYjNKdE1CNFhEVEl5TURNeU5ERTBORGMwTkZvWERUTXlNRE15TkRFME5Ea3lORm93RlRFVE1C'
    'RUdBMVVFQXd3S2MzUmhZMnR6ZEc5eWJUQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FR'
    'b0NnZ0VCQU84TVlvMHhIWmpzVlhIdG4wSDdDb3cvK1ZGMVNRWmQwWXJpNExmWGxwZWUrdVJiOTNtT3Br'
    'OHAxVGoxWkRZejM4UEZaZ2NBTjRQZDUreGNNY1BmNUZZZjd6aTZmMGh5T2ZldzFFQzlWVzNCRkd6OFNw'
    'RngwQStMT2luUVV4b1dNWlZFTWRQVUZQVWEzaEU4MFd3L1J2VUFwMDVUd2JHT0RrdTA4R3htaHNwVlRJ'
    'R2xuQUYwVnZiS0ExTlluUnBmR0Z4eDJ4Q2g5SWxJcXFtWHl1OTZNVThjZ2lBZ3ZkTlBET0wvM1dqcUVr'
    'QVdTZmFmSldzNy9odWtiTkRsNURzQlhSdmpXLzAzb1NSRUUxQ1crRzRmak94K29zMHJVTzRzZ1k3b2tO'
    'N2RndXJ0azhCWlFPSkk4aTN6bW1XRW04Zy8vemNySlJ2YmJtZGJOYzcwRTNadStCVUNBd0VBQVRBTkJn'
    'a3Foa2lHOXcwQkFRc0ZBQU9DQVFFQTBFWGlycm1nbXBMNjd2ZnpiS1Z5b1E5ZmFYZnprL1FyR0crWmxJ'
    'cm5pLytRbUN1UjBRYzR3ZWg2NVAyaXYvb0NIbmRNekl3TUVQR2FzZlA2Vkc2eVVMZDFZUXpta0lRNnFD'
    'eGZEbU5iaElMWUxvQmE5NUl4WmVrcWFjZ1pYb0xSTmlEd3l6YW55NDZyWFJzL21YeVlqUHdsWHluT0d5'
    'L290VW12NnFxcDBJaG95Qk02UjRzVEZaNVJyeWZEWHg3RjNudThuZktpN0xmSnhjUEJ0ckNGNFNnLy9l'
    'NkpnSGpuUXllbUE0SEFPWFBpU1hUbjJnaEtUUi94bzVNRVZvbm4yOTZaM2JqWUdKdUw3bXhSK3JCZHZq'
    'VzdabUJHQ1U2QTFnMUJsa2JqT21seHFGaENTeEF0YXJEU3htM0ZkK3AxVnd5bFNrK0xIZzl0bmJVTDNz'
    'Qkl2Zz09PC9kc2lnOlg1MDlDZXJ0aWZpY2F0ZT48L2RzaWc6WDUwOURhdGE+PGRzaWc6S2V5VmFsdWU+'
    'PGRzaWc6UlNBS2V5VmFsdWU+PGRzaWc6TW9kdWx1cz43d3hpalRFZG1PeFZjZTJmUWZzS2pELzVVWFZK'
    'QmwzUml1TGd0OWVXbDU3NjVGdjNlWTZtVHluVk9QVmtOalBmdzhWbUJ3QTNnOTNuN0Z3eHc5L2tWaC92'
    'T0xwL1NISTU5N0RVUUwxVmJjRVViUHhLa1hIUUQ0czZLZEJUR2hZeGxVUXgwOVFVOVJyZUVUelJiRDlH'
    'OVFDblRsUEJzWTRPUzdUd2JHYUd5bFZNZ2FXY0FYUlc5c29EVTFpZEdsOFlYSEhiRUtIMGlVaXFxWmZL'
    'NzNveFR4eUNJQ0M5MDA4TTR2L2RhT29TUUJaSjlwOGxhenYrRzZSczBPWGtPd0ZkRytOYi9UZWhKRVFU'
    'VUpiNGJoK003SDZpelN0UTdpeUJqdWlRM3QyQzZ1MlR3RmxBNGtqeUxmT2FaWVNieUQvL055c2xHOXR1'
    'WjFzMXp2UVRkbTc0RlE9PTwvZHNpZzpNb2R1bHVzPjxkc2lnOkV4cG9uZW50PkFRQUI8L2RzaWc6RXhw'
    'b25lbnQ+PC9kc2lnOlJTQUtleVZhbHVlPjwvZHNpZzpLZXlWYWx1ZT48L2RzaWc6S2V5SW5mbz48L2Rz'
    'aWc6U2lnbmF0dXJlPjxzYW1sOlN1YmplY3Q+PHNhbWw6TmFtZUlEIEZvcm1hdD0idXJuOm9hc2lzOm5h'
    'bWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6dHJhbnNpZW50Ij5HLTJiMTIxMzc0LWVkMGEtNDk1'
    'MS05NWIxLTVhNGJlOWU3YWU2OTwvc2FtbDpOYW1lSUQ+PHNhbWw6U3ViamVjdENvbmZpcm1hdGlvbiBN'
    'ZXRob2Q9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpjbTpiZWFyZXIiPjxzYW1sOlN1YmplY3RD'
    'b25maXJtYXRpb25EYXRhIEluUmVzcG9uc2VUbz0iaWRfMzhjNjVlNmYtMTI0Yy00NTFmLThmZjgtNDA3'
    'ZTE3OTk4MThlIiBOb3RPbk9yQWZ0ZXI9IjIwMjItMDctMTJUMTc6NDM6NDMuOTM0WiIgUmVjaXBpZW50'
    'PSJodHRwOi8vbG9jYWxob3N0L2F1dGgvc3NvL2NhbGxiYWNrIi8+PC9zYW1sOlN1YmplY3RDb25maXJt'
    'YXRpb24+PC9zYW1sOlN1YmplY3Q+PHNhbWw6Q29uZGl0aW9ucyBOb3RCZWZvcmU9IjIwMjItMDctMTJU'
    'MTc6Mzg6NDMuOTM0WiIgTm90T25PckFmdGVyPSIyMDIyLTA3LTEyVDE3OjM5OjQzLjkzNFoiPjxzYW1s'
    'OkF1ZGllbmNlUmVzdHJpY3Rpb24+PHNhbWw6QXVkaWVuY2U+aHR0cDovL2xvY2FsaG9zdDwvc2FtbDpB'
    'dWRpZW5jZT48L3NhbWw6QXVkaWVuY2VSZXN0cmljdGlvbj48L3NhbWw6Q29uZGl0aW9ucz48c2FtbDpB'
    'dXRoblN0YXRlbWVudCBBdXRobkluc3RhbnQ9IjIwMjItMDctMTJUMTc6Mzg6NDUuOTM4WiIgU2Vzc2lv'
    'bkluZGV4PSIwYjQwZjFiYS1jZWU1LTQ3OGQtYTM1OC1jMzQ1N2M4ZWI1MjE6Ojk1MTQ5MDdlLTg5ZGYt'
    'NDIzMS04OGQxLTczOGI2NTU5NTkyMCIgU2Vzc2lvbk5vdE9uT3JBZnRlcj0iMjAyMi0wNy0xM1QwMzoz'
    'ODo0NS45MzhaIj48c2FtbDpBdXRobkNvbnRleHQ+PHNhbWw6QXV0aG5Db250ZXh0Q2xhc3NSZWY+dXJu'
    'Om9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFjOmNsYXNzZXM6dW5zcGVjaWZpZWQ8L3NhbWw6QXV0aG5D'
    'b250ZXh0Q2xhc3NSZWY+PC9zYW1sOkF1dGhuQ29udGV4dD48L3NhbWw6QXV0aG5TdGF0ZW1lbnQ+PHNh'
    'bWw6QXR0cmlidXRlU3RhdGVtZW50PjxzYW1sOkF0dHJpYnV0ZSBGcmllbmRseU5hbWU9Ikxhc3ROYW1l'
    'IiBOYW1lPSJMYXN0TmFtZSIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0'
    'dHJuYW1lLWZvcm1hdDpiYXNpYyI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHM9Imh0dHA6Ly93'
    'd3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEv'
    'WE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6c3RyaW5nIj5QaW08L3NhbWw6QXR0cmlidXRl'
    'VmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgRnJpZW5kbHlOYW1lPSJGaXJzdE5h'
    'bWUiIE5hbWU9IkZpcnN0TmFtZSIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4w'
    'OmF0dHJuYW1lLWZvcm1hdDpiYXNpYyI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHM9Imh0dHA6'
    'Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIw'
    'MDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6c3RyaW5nIj5HdWlsaGVybWU8L3NhbWw6'
    'QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgRnJpZW5kbHlOYW1l'
    'PSJVc2VybmFtZSIgTmFtZT0iVXNlcm5hbWUiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpT'
    'QU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6YmFzaWMiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhz'
    'PSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3Lncz'
    'Lm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+Z3VpbGhlcm1l'
    'LnBpbTwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBO'
    'YW1lPSJSb2xlIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUt'
    'Zm9ybWF0OmJhc2ljIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5v'
    'cmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hl'
    'bWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPnVtYV9hdXRob3JpemF0aW9uPC9zYW1sOkF0'
    'dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9IlJvbGUiIE5h'
    'bWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6YmFzaWMi'
    'PjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNj'
    'aGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIg'
    'eHNpOnR5cGU9InhzOnN0cmluZyI+bWFuYWdlLWFjY291bnQtbGlua3M8L3NhbWw6QXR0cmlidXRlVmFs'
    'dWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iUm9sZSIgTmFtZUZvcm1hdD0i'
    'dXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDpiYXNpYyI+PHNhbWw6QXR0'
    'cmlidXRlVmFsdWUgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxu'
    'czp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0i'
    'eHM6c3RyaW5nIj5vZmZsaW5lX2FjY2Vzczwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmli'
    'dXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJSb2xlIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6'
    'dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OmJhc2ljIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxu'
    'czp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3'
    'dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPm1hbmFn'
    'ZS1hY2NvdW50PC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmli'
    'dXRlIE5hbWU9IlJvbGUiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRy'
    'bmFtZS1mb3JtYXQ6YmFzaWMiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3'
    'LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hN'
    'TFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+dmlldy1wcm9maWxlPC9zYW1sOkF0'
    'dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9IlJvbGUiIE5h'
    'bWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6YmFzaWMi'
    'PjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNj'
    'aGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIg'
    'eHNpOnR5cGU9InhzOnN0cmluZyI+ZGVmYXVsdC1yb2xlcy1zdGFja3N0b3JtPC9zYW1sOkF0dHJpYnV0'
    'ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PC9zYW1sOkF0dHJpYnV0ZVN0YXRlbWVudD48L3NhbWw6QXNz'
    'ZXJ0aW9uPjwvc2FtbHA6UmVzcG9uc2U+'

)

MOCK_SAML_METADATA_TEXT = (

    '<md:EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:md="urn:'
    'oasis:names:tc:SAML:2.0:metadata" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assert'
    'ion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="{idp_url}"> <md:IDPS'
    'SODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasi'
    's:names:tc:SAML:2.0:protocol"> <md:KeyDescriptor use="signing"> <ds:KeyInfo> <ds'
    ':KeyName>{keyname}</ds:KeyName> <ds:X509Data> <ds:X509Certificate> {certificate}'
    ' </ds:X509Certificate> </ds:X509Data> </ds:KeyInfo> </md:KeyDescriptor> <md:Arti'
    'factResolutionService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Locati'
    'on="{idp_redirect_url}/resolve" index="0"> </md:ArtifactResolutionServ'
    'ice> <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-'
    'POST" Location="{idp_redirect_url}"></md:SingleLogoutService> <md:SingleLogoutSe'
    'rvice Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{id'
    'p_redirect_url}"></md:SingleLogoutService> <md:SingleLogoutService Binding="urn:'
    'oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="{idp_redirect_url}"></'
    'md:SingleLogoutService> <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-form'
    'at:persistent</md:NameIDFormat> <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nam'
    'eid-format:transient</md:NameIDFormat> <md:NameIDFormat>urn:oasis:names:tc:SAML:'
    '1.1:nameid-format:unspecified</md:NameIDFormat> <md:NameIDFormat>urn:oasis:names'
    ':tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat> <md:SingleSignOnServic'
    'e Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{idp_redire'
    'ct_url}"></md:SingleSignOnService> <md:SingleSignOnService Binding="urn:oasis:na'
    'mes:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{idp_redirect_url}"></md:Singl'
    'eSignOnService> <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bin'
    'dings:SOAP" Location="{idp_redirect_url}"></md:SingleSignOnService> <md:SingleSi'
    'gnOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Locatio'
    'n="{idp_redirect_url}"></md:SingleSignOnService> </md:IDPSSODescriptor> </md:Ent'
    'ityDescriptor>'
)

MOCK_REDIRECT_INFO = {
    'headers': {
        'Location': MOCK_REDIRECT_URL
    }
}

MOCK_USER_USERNAME = 'stanley'
MOCK_USER_EMAIL = 'stanley@stackstorm.com'
MOCK_USER_LASTNAME = 'Stormin'
MOCK_USER_FIRSTNAME = 'Stanley'


class MockSamlMetadata(object):

    def __init__(self, text='foobar'):
        self.text = MOCK_SAML_METADATA_TEXT.format(
            idp_url=MOCK_IDP_URL,
            certificate=MOCK_X509_CERT,
            keyname=MOCK_X509_KEYNAME,
            idp_redirect_url=MOCK_REDIRECT_URL
        )


class MockAuthnResponse(object):

    def __init__(self):
        self.ava = {
            'Username': MOCK_USER_USERNAME,
            'Email': MOCK_USER_EMAIL,
            'LastName': MOCK_USER_LASTNAME,
            'FirstName': MOCK_USER_FIRSTNAME
        }


class BaseSAML2Controller(DbTestCase):

    automatically_setup_backend = True
    default_sso_backend_kwargs = {'metadata_url': MOCK_METADATA_URL, 'entity_id': MOCK_ENTITY_ID}
    backend_instance = None

    @classmethod
    @mock.patch.object(
        requests,
        'get',
        mock.MagicMock(return_value=MockSamlMetadata()))
    def setupBackendConfig(cls, sso_backend_kwargs=default_sso_backend_kwargs, **kwargs):
        config.parse_args()
        kwargs_json = json.dumps(sso_backend_kwargs)
        cfg.CONF.set_override(name='sso', override=True, group='auth')
        cfg.CONF.set_override(name='sso_backend', override='saml2', group='auth')
        cfg.CONF.set_override(name='sso_backend_kwargs', override=kwargs_json, group='auth')

        cls.app = TestApp(app.setup_app(), **kwargs)

        # Delay import here otherwise setupClass will not have run.
        from st2auth.controllers.v1 import sso as sso_api_controller
        instance = sso_api_controller.SSO_BACKEND = st2auth_sso.get_sso_backend()

        return instance


    @classmethod
    def setUpClass(cls, **kwargs):
        super(BaseSAML2Controller, cls).setUpClass()

        if cls.automatically_setup_backend:
            cls.backend_instance = BaseSAML2Controller.setupBackendConfig(
                cls.default_sso_backend_kwargs, **kwargs)


# Tests for initialization
class TestSAMLSSOBackend(BaseSAML2Controller):

    automatically_setup_backend = False

    def _test_cls_init_valid_metadata_and_entity(self, backend_config):
        instance = self.setupBackendConfig(backend_config)
        self.assertEqual(instance.entity_id, MOCK_ENTITY_ID)
        self.assertEqual(instance.https_acs_url, MOCK_ACS_URL)
        self.assertEqual(instance.saml_metadata_url, MOCK_METADATA_URL)

        expected_saml_client_settings = {
            'entityid': MOCK_ENTITY_ID,
            'metadata': {'inline': [MockSamlMetadata().text]},
            'service': {
                'sp': {
                    'endpoints': {
                        'assertion_consumer_service': [
                            (MOCK_ACS_URL, saml2.BINDING_HTTP_REDIRECT),
                            (MOCK_ACS_URL, saml2.BINDING_HTTP_POST)
                        ]
                    },
                    'allow_unsolicited': True,
                    'authn_requests_signed': False,
                    'logout_requests_signed': True,
                    'want_assertions_signed': True,
                    'want_response_signed': True
                }
            }
        }

        self.assertDictEqual(instance.saml_client_settings, expected_saml_client_settings)

    def test_cls_init_no_roles(self):
        self._test_cls_init_valid_metadata_and_entity(
            {'metadata_url': MOCK_METADATA_URL, 'entity_id': MOCK_ENTITY_ID})


    def test_cls_init_valid_roles(self):
        self._test_cls_init_valid_metadata_and_entity({
            'metadata_url': MOCK_METADATA_URL, 
            'entity_id': MOCK_ENTITY_ID,
            'role_mapping': {
                'test_role': ['test', '123']
            }
        })

    def test_cls_init_invalid_roles_spec_list_of_number(self):
        self.assertRaisesRegex(TypeError, 
            (
                "invalid 'role_mapping' parameter - it is supposed to be"
                " a dict\[str, list\[str\]\] object or None!"
            ), 
            self._test_cls_init_valid_metadata_and_entity,
            {
                'metadata_url': MOCK_METADATA_URL, 
                'entity_id': MOCK_ENTITY_ID,
                'role_mapping': {
                    'test_role1': ['123', 'role2'],
                    'test_role': [123, 333]
                }
        })

    def test_cls_init_invalid_roles_spec_string(self):
        self.assertRaisesRegex(TypeError, 
            (
                "invalid 'role_mapping' parameter - it is supposed to be"
                " a dict\[str, list\[str\]\] object or None!"
            ), 
            self._test_cls_init_valid_metadata_and_entity,
            {
                'metadata_url': MOCK_METADATA_URL, 
                'entity_id': MOCK_ENTITY_ID,
                'role_mapping': {
                    'test_role': 'test'
                }
        })

    def test_cls_init_missing_args(self):
        self.assertRaisesRegex(
            TypeError, 
            "missing 1 required positional argument: 'entity_id'", 
            self.setupBackendConfig, 
            {'metadata_url': MOCK_METADATA_URL}
        )
        
    def test_cls_init_invalid_args(self):
        self.assertRaisesRegex(
            TypeError, 
            "got an unexpected keyword argument 'invalid'", 
            self.setupBackendConfig, 
            {'metadata_url': MOCK_METADATA_URL, 'entity_id': MOCK_ENTITY_ID, 'invalid': 123}
        )
        

class TestSingleSignOnControllerWithSAML2(BaseSAML2Controller):

    @mock.patch.object(
        saml.SAML2SingleSignOnBackend,
        '_handle_verification_error',
        mock.MagicMock(side_effect=auth_exc.SSOVerificationError('See unit test.')))
    def test_idp_redirect_bad_referer(self):
        headers = {'referer': 'https://hahahaha.fooled.ya'}
        expected_msg = 'Invalid referer -- ' \
                'it should be either some localhost endpoint or the SSO configured entity'
        expected_error = {'faultstring': 'Internal Server Error'}
        response = self.app.get(SSO_REQUEST_V1_PATH, headers=headers, expect_errors=True)
        self.assertTrue(response.status_code, http_client.INTERNAL_SERVER_ERROR)
        self.assertDictEqual(response.json, expected_error)
        self.assertTrue(saml.SAML2SingleSignOnBackend._handle_verification_error.called)
        saml.SAML2SingleSignOnBackend._handle_verification_error.assert_called_with(expected_msg)

    @mock.patch.object(
        saml2.client.Saml2Client,
        'prepare_for_authenticate',
        mock.MagicMock(return_value=(None, MOCK_REDIRECT_INFO)))
    def test_idp_redirect(self):
        headers = {'referer': MOCK_ENTITY_ID}
        response = self.app.get(SSO_REQUEST_V1_PATH, headers=headers, expect_errors=False)
        self.assertTrue(response.status_code, http_client.TEMPORARY_REDIRECT)
        self.assertEqual(response.location, MOCK_REDIRECT_URL)


class TestIdentityProviderCallbackController(BaseSAML2Controller):

    # Helper method for similar test cases.. maybe there's a more 'table-driven' way
    # of doing this but we should be okay :)
    def _test_idp_callback_response_helper(self, expected_response, callback_request, status_code, expected_response_type='json'):
        response = self.app.post_json(SSO_CALLBACK_V1_PATH, callback_request, expect_errors=True)
        self.assertTrue(response.status_code, status_code)

        if expected_response_type == 'json':
            self.assertDictEqual(response.json, expected_response)
        else:
            self.assertEqual(response.body.decode('utf-8'), expected_response)

    # Helper method for triggering a processing of a valid SAML Response (the one from the mock :)
    def _test_idp_callback_valid_response_helper(self, expected_response, relay_state, status_code, expected_response_type='json'):
        # Making sure we ignore old responses :)
        old = saml.SAML2SingleSignOnBackend._get_saml_client
        def wrapper(self):
            client = old(self)
            client.config.accepted_time_diff = 10000000
            return client
        saml.SAML2SingleSignOnBackend._get_saml_client = wrapper
        # Create a request in the database for flow to proceed properly :)
        create_web_sso_request(MOCK_SAML_RESPONSE_REQUEST_ID)

        self._test_idp_callback_response_helper(
            expected_response,
            {'SAMLResponse': [MOCK_SAML_RESPONSE], 'RelayState': relay_state},
            status_code,
            expected_response_type
        )

        saml.SAML2SingleSignOnBackend._get_saml_client = old


    def test_idp_callback_missing_response(self):
        self._test_idp_callback_response_helper(
            {'faultstring': 'The SAMLResponse attribute is missing.'},
            {},
            http_client.UNAUTHORIZED
        )

    def test_idp_callback_null_response(self):
        self._test_idp_callback_response_helper(
            {'faultstring': 'The SAMLResponse attribute is null.'},
            { 'SAMLResponse': None},
            http_client.UNAUTHORIZED
        )

    def test_idp_callback_zerolen_response(self):
        self._test_idp_callback_response_helper(
            {'faultstring': 'The SAMLResponse attribute should be a list of one or more strings'},
            { 'SAMLResponse': []},
            http_client.UNAUTHORIZED
        )

    def test_idp_callback_nonarray_response(self):
        self._test_idp_callback_response_helper(
            {'faultstring': 'The SAMLResponse attribute should be a list of one or more strings'},
            { 'SAMLResponse': "test"},
            http_client.UNAUTHORIZED
        )

    def test_idp_callback_nonstring_response(self):
        self._test_idp_callback_response_helper(
            {'faultstring': 'The SAMLResponse attribute should be a list of one or more strings'},
            { 'SAMLResponse': [1]},
            http_client.UNAUTHORIZED
        )

    @mock.patch.object(
        saml.SAML2SingleSignOnBackend,
        'get_request_id_from_response',
        mock.MagicMock(return_value=None))
    def test_idp_callback_invalid_request_id(self):
        self._test_idp_callback_response_helper(
            {'faultstring': 'Invalid request id coming from SAML response'},
            { 'SAMLResponse': [MOCK_SAML_RESPONSE]},
            http_client.UNAUTHORIZED
        )

    # Mock internal call to make it through
    @mock.patch.object(
        saml2.response.StatusResponse,
        'issue_instant_ok',
        mock.MagicMock(return_value=True))
    def test_idp_callback_old_response(self):
        self._test_idp_callback_response_helper(
            {'faultstring': 'SAML response is too old!'},
            { 'SAMLResponse': [MOCK_SAML_RESPONSE]},
            http_client.UNAUTHORIZED
        )

    def test_idp_callback_empty_relay_state(self):
        self._test_idp_callback_valid_response_helper(
            {'faultstring': 'The RelayState attribute is empty.'},
            [],
            http_client.UNAUTHORIZED
        )
    def test_idp_callback_null_relay_state(self):
        self._test_idp_callback_valid_response_helper(
            {'faultstring': 'The RelayState attribute is null.'},
            None,
            http_client.UNAUTHORIZED
        )

    def test_idp_callback_relay_state_missing_referer(self):
        self._test_idp_callback_valid_response_helper(
            {'faultstring': 'The RelayState is missing the referer'},
            [json.dumps({})],
            http_client.UNAUTHORIZED
        )

    def test_idp_callback_relay_state_bad_referer(self):
        self._test_idp_callback_valid_response_helper(
            {'faultstring': 'The RelayState referer [https://foobar] is not allowed. It must come from the trusted SAML entity'},
            [json.dumps({'referer': 'https://foobar'})],
            http_client.UNAUTHORIZED
        )


    def test_idp_callback(self):
        self._test_idp_callback_valid_response_helper(
            {'faultstring': 'The RelayState referer [https://foobar] is not allowed. It must come from the trusted SAML entity'},
            [json.dumps({'referer': 'https://foobar'})],
            http_client.OK
        )

    def test_idp_callback_empty_relay_state(self):
        self._test_idp_callback_valid_response_helper(
            {'faultstring': "The RelayState attribute is null."},
            None,
            http_client.UNAUTHORIZED,
        )

    def test_idp_callback_with_relay_state(self):
        self._test_idp_callback_valid_response_helper(
            st2auth.controllers.v1.sso.CALLBACK_SUCCESS_RESPONSE_BODY % MOCK_REFERER,
            [json.dumps({'referer': MOCK_REFERER})],
            http_client.OK,
            'str'
        )
