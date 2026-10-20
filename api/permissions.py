from rest_framework import permissions

class IsSecurityAnalystOrAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
            
        allowed_groups = ['Analysts', 'Admin']
        return request.user.groups.filter(name__in=allowed_groups).exists()