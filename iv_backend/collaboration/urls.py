from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import TeamViewSet, TeamMembershipViewSet

router = DefaultRouter()
router.register(r'team', TeamViewSet, basename='team')
router.register(r'team-membership', TeamMembershipViewSet, basename='team-membership')

urlpatterns = [
    path('api/', include(router.urls)),
]
