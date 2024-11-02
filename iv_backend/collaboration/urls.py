from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import TeamViewSet, TeamMembershipViewSet, CreateInvitationView, RespondInvitationView, InvitationListView

router = DefaultRouter()
router.register(r'team', TeamViewSet, basename='team')
router.register(r'team-membership', TeamMembershipViewSet, basename='team-membership')

urlpatterns = [
    path('api/', include(router.urls)),
    path('teams/<int:team_id>/invite/', CreateInvitationView.as_view(), name='create-invitation'),
    path('invitations/<int:invitation_id>/respond/', RespondInvitationView.as_view(), name='respond-invitation'),
    path('invitations/', InvitationListView.as_view(), name='invitation-list'),
]
