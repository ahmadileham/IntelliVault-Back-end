import hashlib
import requests
from collections import defaultdict
from typing import List, Dict, Any
from vault.utils import AESEncryption
from .models import PasswordAnalysis, PasswordIssue
from .utils import PasswordSimilarityChecker
import logging
from vault.models import LoginInfo, Vault

logger = logging.getLogger(__name__)

class HaveIBeenPwnedAPI:
    BASE_URL = "https://api.pwnedpasswords.com/range/"
    
    @staticmethod
    def check_password(password: str) -> int:
        """
        Check if a password has been exposed in data breaches.
        Returns the number of times the password was exposed.
        """
        password_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = password_hash[:5], password_hash[5:]
        
        try:
            response = requests.get(f"{HaveIBeenPwnedAPI.BASE_URL}{prefix}")
            response.raise_for_status()
            
            hashes = (line.split(':') for line in response.text.splitlines())
            for hash_suffix, count in hashes:
                if hash_suffix == suffix:
                    return int(count)
            return 0
            
        except requests.RequestException as e:
            logger.error(f"Error checking HaveIBeenPwned API: {str(e)}")
            return 0

class PasswordAnalyzer:
    def __init__(self):
        self.aes = AESEncryption()
        self.similarity_checker = PasswordSimilarityChecker()
        self.hibp_api = HaveIBeenPwnedAPI()
    
    def analyze_vault(self, vault, user) -> PasswordAnalysis:
        """Perform comprehensive password analysis on a vault."""
        # Create new analysis instance
        analysis = PasswordAnalysis.objects.create(
            user=user,
            vault=vault
        )
        
        # Get all login infos from the vault
        login_infos = vault.logininfo_set.all()
        
        # Decrypt passwords and store mapping
        password_map = {}  # Maps password to list of LoginInfo objects
        decrypted_passwords = {}  # Maps LoginInfo ID to decrypted password
        
        for login_info in login_infos:
            try:
                decrypted_pass = self.aes.decrypt_login_password(login_info.login_password)
                decrypted_passwords[login_info.id] = decrypted_pass
                
                # Group by password for reuse detection
                if decrypted_pass in password_map:
                    password_map[decrypted_pass].append(login_info)
                else:
                    password_map[decrypted_pass] = [login_info]
                    
            except Exception as e:
                logger.error(f"Error decrypting password for LoginInfo {login_info.id}: {str(e)}")
                continue
        
        # Analyze reused passwords
        self._analyze_reused_passwords(analysis, password_map)
        
        # Analyze similar passwords
        self._analyze_similar_passwords(analysis, decrypted_passwords)
        
        # Check for breached passwords
        self._analyze_breached_passwords(analysis, decrypted_passwords)
        
        # Update analysis counts
        analysis.reused_passwords_count = analysis.issues.filter(
            issue_type=PasswordIssue.REUSED).count()
        analysis.similar_passwords_count = analysis.issues.filter(
            issue_type=PasswordIssue.SIMILAR).count()
        analysis.breached_passwords_count = analysis.issues.filter(
            issue_type=PasswordIssue.BREACHED).count()
        analysis.save()
        
        return analysis
    
    def _analyze_reused_passwords(self, analysis, password_map: Dict[str, List]):
        """Identify and record reused passwords."""
        for password, login_infos in password_map.items():
            if len(login_infos) > 1:
                for login_info in login_infos:
                    PasswordIssue.objects.create(
                        analysis=analysis,
                        login_info=login_info,
                        issue_type=PasswordIssue.REUSED,
                        details={
                            'reuse_count': len(login_infos),
                            'reused_in': [li.login_username for li in login_infos if li.id != login_info.id]
                        }
                    )
    
    def _analyze_similar_passwords(self, analysis, decrypted_passwords: Dict[int, str]):
        """Check passwords against breached password dataset using similarity model."""
        for login_info_id, password in decrypted_passwords.items():
            similarity_score = self.similarity_checker.calculate_similarity(password)
            
            if similarity_score > 0.5:  # If similarity is greater than 50%
                PasswordIssue.objects.create(
                    analysis=analysis,
                    login_info_id=login_info_id,
                    issue_type=PasswordIssue.SIMILAR,
                    similarity_score=similarity_score,
                    details={
                        'similarity_percentage': round(similarity_score, 2)
                    }
                )
    
    def _analyze_breached_passwords(self, analysis, decrypted_passwords: Dict[int, str]):
        """Check passwords against HaveIBeenPwned API."""
        for login_info_id, password in decrypted_passwords.items():
            breach_count = self.hibp_api.check_password(password)
            
            if breach_count > 0:
                PasswordIssue.objects.create(
                    analysis=analysis,
                    login_info_id=login_info_id,
                    issue_type=PasswordIssue.BREACHED,
                    details={'times_exposed': breach_count}
                ) 