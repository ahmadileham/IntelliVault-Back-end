from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import (
    VaultViewSet,
    LoginInfoViewSet,
    FileViewSet,
    ShareItemView,
    ShareVaultView,
    AccessSharedItemView,
    AccessSharedVaultView,
    FileDownloadView,
     VaultItemsView,
     TeamVaultActionRequestViewSet
)


router = DefaultRouter()
router.register(r'vault', VaultViewSet, basename='vault')
router.register(r'logininfo', LoginInfoViewSet, basename='login-info')
router.register(r'file', FileViewSet, basename='file')
router.register(r'team-vault-action-request', TeamVaultActionRequestViewSet, basename='team-vault-action-request')

urlpatterns = [
    path('api/', include(router.urls)),
    path('file/download/<int:file_id>/',
         FileDownloadView.as_view(), name='file-download-owner'),
    path('file/download/<int:file_id>/<str:share_link>/',
         FileDownloadView.as_view(), name='file-download-shared'),


    # Sharing URLs
    path('share/vault/<int:vault_id>/',
         ShareVaultView.as_view(), name='share-vault'), # This url must be above to prevent 'vault' from being treated as 'item_type'
    path('share/<str:item_type>/<int:item_id>/', 
         ShareItemView.as_view(), name='share-item'),

    # Accessing Shared Items/Vaults
    path('access/item/<str:share_link>/',
         AccessSharedItemView.as_view(), name='access-shared-item'),
    path('access/vault/<str:share_link>/',
         AccessSharedVaultView.as_view(), name='access-shared-vault'),

     path('<int:vault_id>/items/', VaultItemsView.as_view(), name='vault-items'),
]
