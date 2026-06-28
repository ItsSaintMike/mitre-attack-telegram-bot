import requests
import json
from typing import Dict, List, Optional
from config import Config

class MitreAPI:
    def __init__(self):
        self.api_url = Config.MITRE_API_URL
        self.attack_url = Config.MITRE_ATTACK_URL
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def fetch_attack_data(self) -> Dict:
        try:
            response = self.session.get(self.api_url, timeout=60)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Ошибка загрузки: {e}")
            return {}

    def parse_stix_data(self, stix_data: Dict) -> Dict:
        techniques = []
        tactics = []

        # Если данные в формате STIX 2.1 (с objects)
        if 'objects' in stix_data:
            for obj in stix_data['objects']:
                if obj.get('type') == 'x-mitre-tactic':
                    external_id = obj.get('external_references', [{}])[0].get('external_id', '')
                    tactics.append({
                        'id': external_id,
                        'name': obj.get('name', ''),
                        'description': obj.get('description', ''),
                        'url': f"{self.attack_url}/tactics/{external_id}"
                    })
                elif obj.get('type') == 'attack-pattern':
                    tactic_phases = obj.get('kill_chain_phases', [])
                    tactic_name = tactic_phases[0].get('phase_name', '') if tactic_phases else ''
                    external_refs = obj.get('external_references', [{}])
                    technique_id = ''
                    for ref in external_refs:
                        if ref.get('source_name') == 'mitre-attack':
                            technique_id = ref.get('external_id', '')
                            break
                    if technique_id:
                        techniques.append({
                            'id': technique_id,
                            'name': obj.get('name', ''),
                            'description': obj.get('description', ''),
                            'tactic_name': tactic_name,
                            'tactic_id': self._get_tactic_id_by_name(tactic_name),
                            'platform': ', '.join(obj.get('x_mitre_platforms', [])),
                            'url': f"{self.attack_url}/techniques/{technique_id}",
                            'created_date': obj.get('created', ''),
                            'modified_date': obj.get('modified', ''),
                            'is_deprecated': obj.get('x_mitre_deprecated', False)
                        })
        
        # Если данные просто список техник (альтернативный формат)
        elif isinstance(stix_data, list):
            for obj in stix_data:
                if obj.get('type') == 'attack-pattern':
                    external_refs = obj.get('external_references', [{}])
                    technique_id = ''
                    for ref in external_refs:
                        if ref.get('source_name') == 'mitre-attack':
                            technique_id = ref.get('external_id', '')
                            break
                    if technique_id:
                        tactics_list = obj.get('kill_chain_phases', [])
                        tactic_name = tactics_list[0].get('phase_name', '') if tactics_list else ''
                        techniques.append({
                            'id': technique_id,
                            'name': obj.get('name', ''),
                            'description': obj.get('description', ''),
                            'tactic_name': tactic_name,
                            'tactic_id': self._get_tactic_id_by_name(tactic_name),
                            'platform': ', '.join(obj.get('x_mitre_platforms', [])),
                            'url': f"{self.attack_url}/techniques/{technique_id}",
                            'created_date': obj.get('created', ''),
                            'modified_date': obj.get('modified', ''),
                            'is_deprecated': obj.get('x_mitre_deprecated', False)
                        })

        return {'techniques': techniques, 'tactics': tactics}

    def _get_tactic_id_by_name(self, tactic_name: str) -> str:
        tactic_map = {
            'reconnaissance': 'TA0043',
            'resource-development': 'TA0042',
            'initial-access': 'TA0001',
            'execution': 'TA0002',
            'persistence': 'TA0003',
            'privilege-escalation': 'TA0004',
            'defense-evasion': 'TA0005',
            'credential-access': 'TA0006',
            'discovery': 'TA0007',
            'lateral-movement': 'TA0008',
            'collection': 'TA0009',
            'command-and-control': 'TA0011',
            'exfiltration': 'TA0010',
            'impact': 'TA0040'
        }
        return tactic_map.get(tactic_name.lower(), '')
