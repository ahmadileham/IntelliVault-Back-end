import random
import string
from rest_framework import viewsets, status
from rest_framework.response import Response
from .models import GeneratedPassword, PasswordAnalysis, PasswordIssue
from .serializers import GeneratedPasswordSerializer, PasswordCreateSerializer, PasswordAnalysisSerializer, PasswordIssueSerializer
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import action
from .services import PasswordAnalyzer
from django.db.models import Q
from rest_framework.views import APIView
from .services import HaveIBeenPwnedAPI
from .utils import PasswordSimilarityChecker

# Helper function to generate password based on user preferences
def generate_password(length, use_uppercase, use_numbers, use_special_chars):
    characters = string.ascii_lowercase
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_numbers:
        characters += string.digits
    if use_special_chars:
        characters += string.punctuation

    password = ''.join(random.choice(characters) for _ in range(length))
    return password

class GeneratedPasswordViewSet(viewsets.ModelViewSet):
    queryset = GeneratedPassword.objects.all()
    serializer_class = GeneratedPasswordSerializer
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        # Use a different serializer for password creation
        if self.action == 'create':
            return PasswordCreateSerializer
        return GeneratedPasswordSerializer

    def create(self, request, *args, **kwargs):
        # Validate user input using PasswordCreateSerializer
        create_serializer = self.get_serializer(data=request.data)
        create_serializer.is_valid(raise_exception=True)

        # Extract options from the request data
        length = request.data.get('length', 12)  # Default length is 12
        use_uppercase = request.data.get('use_uppercase', False)
        use_numbers = request.data.get('use_numbers', False)
        use_special_chars = request.data.get('use_special_chars', False)

        # Generate the password based on user preferences
        generated_password = generate_password(length, use_uppercase, use_numbers, use_special_chars)

        # Determine password strength (simple example: length-based)
        strength = length >= 12 and use_uppercase and use_numbers and use_special_chars

        # Save the generated password and its metadata
        password_instance = GeneratedPassword.objects.create(
            generated_by=request.user,  # Use the authenticated user for generated_by
            password=generated_password,
            strength=strength
        )

        # Return the created password with GeneratedPasswordSerializer
        response_serializer = GeneratedPasswordSerializer(password_instance)
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)

    def list(self, request, *args, **kwargs):
        # Retrieve the recent passwords for the authenticated user
        queryset = self.get_queryset().filter(generated_by=request.user).order_by('-date_generated')[:10]
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class PasswordAnalysisViewSet(viewsets.ModelViewSet):
    serializer_class = PasswordAnalysisSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return PasswordAnalysis.objects.filter(user=self.request.user)
    
    @action(detail=False, methods=['post'])
    def analyze_passwords(self, request):
        
        # Perform the analysis
        analyzer = PasswordAnalyzer()
        analysis = analyzer.perform_analysis(request.user)
        
        serializer = PasswordAnalysisSerializer(analysis)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def latest_analysis(self, request):
            
        analysis = PasswordAnalysis.objects.filter(
            user=request.user
        ).order_by('-analysis_date').first()
        
        if not analysis:
            return Response(
                {'error': 'No analysis found for this vault'}, 
                status=status.HTTP_404_NOT_FOUND
            )
            
        serializer = PasswordAnalysisSerializer(analysis)
        return Response(serializer.data)
    

class PasswordIssueViewSet(viewsets.ModelViewSet):
    serializer_class = PasswordIssueSerializer
    permission_classes = [IsAuthenticated]
    queryset = PasswordIssue.objects.all()

    # Get issues from a specific analysis
    @action(detail=False, methods=['get'])
    def get_issues_from_analysis(self, request):
        analysis = PasswordAnalysis.objects.filter(user=request.user).order_by('-analysis_date').first()
        if not analysis:
            return Response({'error': 'No analysis found for this vault'}, status=status.HTTP_404_NOT_FOUND)

        issues = analysis.issues.all()
        grouped_issues = {}

        for issue in issues:
            login_info_id = issue.login_info.id
            if login_info_id not in grouped_issues:
                grouped_issues[login_info_id] = {
                    'login_info': issue.login_info,
                    'issues': []
                }
            grouped_issues[login_info_id]['issues'].append(issue)

        # Prepare the response data
        response_data = []
        for entry in grouped_issues.values():
            response_data.append({
                'login_info': {
                    'id': entry['login_info'].id,
                    'login_username': entry['login_info'].login_username,
                    # Add other fields from LoginInfo as needed
                },
                'issues': [
                    {
                        'issue_type': issue.issue_type,
                        'similarity_score': issue.similarity_score,
                        'details': issue.details,
                    } for issue in entry['issues']
                ]
            })

        return Response(response_data)

class CheckBreachView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        password = request.data.get('password')
        if not password:
            return Response({'error': 'Password is required.'}, status=status.HTTP_400_BAD_REQUEST)

        hibp_api = HaveIBeenPwnedAPI()
        breach_count = hibp_api.check_password(password)

        return Response({'breach_count': breach_count}, status=status.HTTP_200_OK)

class CheckSimilarityView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        password = request.data.get('password')
        if not password:
            return Response({'error': 'Password is required.'}, status=status.HTTP_400_BAD_REQUEST)

        similarity_checker = PasswordSimilarityChecker()
        similarity_score = similarity_checker.calculate_similarity(password)

        return Response({'similarity_score': similarity_score}, status=status.HTTP_200_OK)
