from rest_framework.throttling import SimpleRateThrottle

from .models import hash_api_key


class TenantRateThrottle(SimpleRateThrottle):
    scope = 'tenant_ingest' 

    def get_cache_key(self, request, view):
        api_key = request.META.get('HTTP_X_API_KEY')
        
        if not api_key:
            return None
            
        return self.cache_format % {
            'scope': self.scope,
            'identifier': hash_api_key(api_key)
        }