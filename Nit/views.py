from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse, HttpResponse
from django.contrib.auth.models import User
from django.core.paginator import Paginator
from django.http import JsonResponse, HttpResponse, FileResponse
from django.contrib.gis.geos import GEOSGeometry, MultiPolygon, Polygon
from django.db.models import Count, Sum, Avg, Q
from django.db import connection, transaction
from django.utils import timezone
from datetime import datetime
from django.core.files.storage import default_storage
from django.contrib.auth.forms import UserCreationForm
import logging
from django.core.files.base import ContentFile
from django.views.decorators.csrf import csrf_exempt
from decimal import Decimal
import json
import os
import csv
import uuid
from .decorators import surveyor_required, admin_required, cbe_required, taxcollector_required
from .models import (
    Data, Surveyor, Ward, UserProfile, Assessment, CBE, Attendance, 
    BuildingData, PointData, Road, PolygonFeature, PasswordResetToken,
    Building, Corporation
)
from .utils import *
from .exports import *
from .forms import *

logger = logging.getLogger(__name__)


# =====================================
# ADMIN AUTHENTICATION VIEWS
# =======================================

def admin_login_view(request):
    """Admin login page with role-based redirection"""
    if request.user.is_authenticated:
        try:
            if request.user.profile.role == 'admin' or request.user.is_superuser:
                return redirect('admin_dashboard')
            elif request.user.profile.role == 'surveyor':
                return redirect('surveyor_dashboard')
            elif request.user.profile.role == 'cbe':
                return redirect('cbe_dashboard')
            else:
                return redirect('home')
        except UserProfile.DoesNotExist:
            return redirect('home')
    
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        if username and password:
            user = authenticate(request, username=username, password=password)
            if user is not None:
                try:
                    if user.is_superuser or (hasattr(user, 'profile') and user.profile.role == 'admin' and user.profile.is_active):
                        login(request, user)
                        messages.success(request, f'Welcome back Admin, {user.username}!')
                        return redirect('admin_dashboard')
                    else:
                        messages.error(request, 'Access denied. You do not have admin privileges.')
                        return render(request, 'Nit/admin_login.html')
                except UserProfile.DoesNotExist:
                    if user.is_superuser:
                        login(request, user)
                        messages.success(request, f'Welcome back Super Admin, {user.username}!')
                        return redirect('admin_dashboard')
                    messages.error(request, 'User profile not found. Please contact administrator.')
                    return render(request, 'Nit/admin_login.html')
            else:
                messages.error(request, 'Invalid username or password.')
        else:
            messages.error(request, 'Please enter both username and password.')
    
    return render(request, 'Nit/admin_login.html')


def admin_logout_view(request):
    """Admin logout view"""   
    logout(request)
    messages.success(request, 'You have been logged out successfully.')
    return redirect('admin_login')


# ============================================
# AUTHENTICATION VIEWS
# ============================================

def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        if username and password:
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                messages.success(request, f'Welcome back, {user.username}!')
                return redirect('dashboard')
            else:
                messages.error(request, 'Invalid username or password.')
        else:
            messages.error(request, 'Please enter both username and password.')
    
    # ✅ ALWAYS return a response for GET requests
    return render(request, 'Nit/login.html')

def logout_view(request):
    logout(request)
    messages.success(request, 'You have been logged out successfully.')
    return redirect('login')


def register_view(request):
    """Register a new user"""
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            username = form.cleaned_data.get('username')
            raw_password = form.cleaned_data.get('password1')
            
            user = authenticate(username=username, password=raw_password)
            if user is not None:
                login(request, user)
                messages.success(request, f'Account created for {username}! Welcome to GIS Survey.')
                return redirect('dashboard')
            else:
                messages.error(request, 'Authentication failed. Please try logging in.')
                return redirect('login')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f'{field}: {error}')
    else:
        form = UserCreationForm()
    
    return render(request, 'Nit/register.html', {'form': form})


@login_required
def dashboard_redirect(request):
    """Redirect users to their appropriate dashboard based on role"""
    if request.user.is_superuser:
        profile, created = UserProfile.objects.get_or_create(user=request.user)
        if created or profile.role not in ['super_admin', 'admin']:
            profile.role = 'super_admin'
            profile.save()
        return redirect('admin_dashboard')
    
    try:
        role = request.user.profile.role
    except UserProfile.DoesNotExist:
        UserProfile.objects.create(user=request.user, role='surveyor')
        role = 'surveyor'
    
    role_urls = {
        'admin': 'admin_dashboard',
        'super_admin': 'admin_dashboard',
        'surveyor': 'surveyor_dashboard',
        'cbe': 'cbe_dashboard',
        'taxcollector': 'taxcollector_dashboard',
    }
    
    return redirect(role_urls.get(role, 'surveyor_dashboard'))


# ============================================
# FORGET PASSWORD
# ============================================

def forget_password(request):
    return render(request, 'Nit/forget.html')


def forget_email(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        user_profile = UserProfile.objects.filter(user__email=email).first()
        
        if user_profile:
            import secrets
            token = secrets.token_urlsafe(32)
            PasswordResetToken.objects.update_or_create(
                email=email,
                defaults={'token': token}
            )
            user_profile.password_reset_token = token
            user_profile.save()
            messages.success(request, 'Password reset link sent to your email.')
            return redirect('login')
        else:
            messages.error(request, 'Email not found.')
    
    return render(request, 'Nit/forget.html')


def reset_password_form(request, token):
    email = request.GET.get('email')
    reset_record = PasswordResetToken.objects.filter(token=token, email=email).first()
    
    if not reset_record:
        messages.error(request, 'Invalid or expired reset token.')
        return redirect('login')
    
    return render(request, 'Nit/reset.html', {'token': token, 'email': email})


def reset_password(request):
    if request.method == 'POST':
        token = request.POST.get('token')
        email = request.POST.get('email')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        
        if password != password2:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'Nit/reset.html', {'token': token, 'email': email})
        
        reset_record = PasswordResetToken.objects.filter(token=token, email=email).first()
        
        if not reset_record:
            messages.error(request, 'Invalid or expired reset token.')
            return redirect('login')
        
        user = User.objects.filter(email=email).first()
        if user:
            user.set_password(password)
            user.save()
            profile = UserProfile.objects.filter(user=user).first()
            if profile:
                profile.password_reset_token = None
                profile.save()
            reset_record.delete()
            messages.success(request, 'Password reset successfully! Please login.')
            return redirect('login')
        else:
            messages.error(request, 'User not found.')
    
    return redirect('login')


# ============================================
# HOME & COMMON PAGES
# ============================================

@login_required
def home_view(request):
    """Home page with dashboard statistics"""
    from .models import Building, Corporation, Assessment
    
    try:
        # Get counts safely with error handling
        total_buildings = Building.objects.count()
        total_corporations = Corporation.objects.count()
        active_buildings = Building.objects.filter(is_active=True).count()
        
        # Get corporation stats safely
        corporation_stats = []
        try:
            for corp in Corporation.objects.all():
                corp_buildings = corp.buildings.all()
                corporation_stats.append({
                    'name': corp.name,
                    'count': corp_buildings.count(),
                    'id': corp.id,
                })
        except Exception as e:
            print(f"Error getting corporation stats: {e}")
            corporation_stats = []
        
        # Get recent buildings
        recent_buildings = Building.objects.order_by('-created_at')[:10]
        
        # Get building type counts
        residential_count = Building.objects.filter(building_type='RESIDENTIAL').count()
        commercial_count = Building.objects.filter(building_type='COMMERCIAL').count()
        industrial_count = Building.objects.filter(building_type='INDUSTRIAL').count()
        
        # Get survey counts safely
        total_surveys = 0
        active_surveys = 0
        try:
            total_surveys = Assessment.objects.count()
            active_surveys = Assessment.objects.filter(status='pending').count()
        except Exception as e:
            print(f"Error getting survey counts: {e}")
        
        context = {
            'total_buildings': total_buildings,
            'total_corporations': total_corporations,
            'active_buildings': active_buildings,
            'corporation_stats': corporation_stats,
            'recent_buildings': recent_buildings,
            'residential_count': residential_count,
            'commercial_count': commercial_count,
            'industrial_count': industrial_count,
            'total_surveys': total_surveys,
            'active_surveys': active_surveys,
        }
        
        return render(request, 'Nit/home.html', context)
        
    except Exception as e:
        print(f"Error in home_view: {e}")
        import traceback
        traceback.print_exc()
        
        # Return basic context
        context = {
            'total_buildings': 0,
            'total_corporations': 0,
            'active_buildings': 0,
            'corporation_stats': [],
            'recent_buildings': [],
            'residential_count': 0,
            'commercial_count': 0,
            'industrial_count': 0,
            'total_surveys': 0,
            'active_surveys': 0,
        }
        return render(request, 'Nit/home.html', context)

# ============================================
# SIMPLE VIEW FUNCTIONS
# ============================================

@login_required
def about_view(request):
    """About page"""
    return render(request, 'Nit/about.html', {'page_title': 'About'})

@login_required
def wards_view(request):
    """Wards page"""
    from .models import Ward
    wards = Ward.objects.filter(is_active=True) if hasattr(Ward, 'objects') else []
    return render(request, 'Nit/wards.html', {'wards': wards, 'page_title': 'Wards'})

@login_required
def profile_view(request):
    """Profile page"""
    return render(request, 'Nit/profile.html', {'user': request.user, 'page_title': 'Profile'})

@login_required
def gis_view(request):
    """GIS page"""
    context = {
        'page_title': 'GIS Dashboard',
        'active_count': 4,
        'total_layers': 12,
        'recent_queries': 28,
    }
    return render(request, 'Nit/gis.html', context)

@login_required
def reports_view(request):
    """Reports page"""
    context = {
        'page_title': 'Reports',
        'total_reports': 45,
        'scheduled_reports': 8,
        'export_formats': ['PDF', 'CSV', 'Excel', 'GeoJSON'],
    }
    return render(request, 'Nit/reports.html', context)

@login_required
def property_view(request):
    """Property page"""
    from .models import Building
    buildings = Building.objects.all()
    context = {
        'page_title': 'Properties',
        'buildings': buildings,
        'total': buildings.count(),
    }
    return render(request, 'Nit/property.html', context)





@login_required
def advanced_search(request):
    """Advanced search page"""
    context = {
        'page_title': 'Advanced Search',
        'wards': [],  # Add wards if available
    }
    return render(request, 'Nit/advanced_search.html', context)
@login_required
def profile_view(request):
    if request.method == 'POST':
        if 'update_profile' in request.POST:
            username = request.POST.get('username')
            email = request.POST.get('email')
            first_name = request.POST.get('first_name')
            last_name = request.POST.get('last_name')
            
            if User.objects.filter(username=username).exclude(id=request.user.id).exists():
                messages.error(request, 'Username already taken.')
            else:
                request.user.username = username
                request.user.email = email
                request.user.first_name = first_name
                request.user.last_name = last_name
                request.user.save()
                messages.success(request, 'Profile updated successfully!')
        
        elif 'change_password' in request.POST:
            current_password = request.POST.get('current_password')
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')
            
            if not request.user.check_password(current_password):
                messages.error(request, 'Current password is incorrect.')
            elif len(new_password) < 8:
                messages.error(request, 'Password must be at least 8 characters long.')
            elif new_password != confirm_password:
                messages.error(request, 'New passwords do not match.')
            else:
                request.user.set_password(new_password)
                request.user.save()
                messages.success(request, 'Password changed successfully! Please login again.')
                return redirect('login')
        
        return redirect('profile')
    
    return render(request, 'Nit/profile.html', {'user': request.user})


# ============================================
# PROPERTY TYPE VIEWS
# ============================================

@login_required
def property_view(request):
    property_type = request.GET.get('type', 'all')
    
    if property_type == 'commercial':
        assessments = Assessment.objects.filter(property_type='commercial')
        title = 'Commercial Buildings'
    elif property_type == 'industrial':
        assessments = Assessment.objects.filter(property_type='industrial')
        title = 'Industrial Buildings'
    elif property_type == 'residential':
        assessments = Assessment.objects.filter(property_type='residential')
        title = 'Residential Properties'
    else:
        assessments = Assessment.objects.all()
        title = 'All Properties'
    
    total_parcels = Assessment.objects.count()
    total_mapped = assessments.count()
    mapped_percentage = int((total_mapped / total_parcels * 100)) if total_parcels > 0 else 0
    
    context = {
        'assessments': assessments,
        'title': title,
        'property_type': property_type,
        'total': assessments.count(),
        'total_parcels': total_parcels,
        'total_mapped': total_mapped,
        'mapped_percentage': mapped_percentage,
        'residential_count': Assessment.objects.filter(property_type='residential').count(),
        'commercial_count': Assessment.objects.filter(property_type='commercial').count(),
        'industrial_count': Assessment.objects.filter(property_type='industrial').count(),
    }
    return render(request, 'Nit/property.html', context)


@login_required
def residential_view(request):
    assessments = Assessment.objects.filter(property_type='residential').order_by('-created_at')
    total_parcels = assessments.count()
    occupied = assessments.filter(status='completed').count()
    vacant = assessments.filter(status='pending').count()
    rented = assessments.filter(status='verified').count()
    
    context = {
        'assessments': assessments,
        'total_parcels': total_parcels,
        'occupied': occupied,
        'vacant': vacant,
        'rented': rented,
        'page_title': 'Residential Properties',
        'residential_count': Assessment.objects.filter(property_type='residential').count(),
        'commercial_count': Assessment.objects.filter(property_type='commercial').count(),
        'industrial_count': Assessment.objects.filter(property_type='industrial').count(),
    }
    return render(request, 'Nit/residential.html', context)


@login_required
def commercial_view(request):
    assessments = Assessment.objects.filter(property_type='commercial').order_by('-created_at')
    
    context = {
        'assessments': assessments,
        'total_parcels': assessments.count(),
        'page_title': 'Commercial Properties',
        'residential_count': Assessment.objects.filter(property_type='residential').count(),
        'commercial_count': Assessment.objects.filter(property_type='commercial').count(),
        'industrial_count': Assessment.objects.filter(property_type='industrial').count(),
    }
    return render(request, 'Nit/commercial.html', context)


@login_required
def industrial_view(request):
    assessments = Assessment.objects.filter(property_type='industrial').order_by('-created_at')
    
    context = {
        'assessments': assessments,
        'total_parcels': assessments.count(),
        'page_title': 'Industrial Properties',
        'residential_count': Assessment.objects.filter(property_type='residential').count(),
        'commercial_count': Assessment.objects.filter(property_type='commercial').count(),
        'industrial_count': Assessment.objects.filter(property_type='industrial').count(),
    }
    return render(request, 'Nit/industrial.html', context)


@login_required
def gis_view(request):
    context = {
        'active_count': 4,
        'total_layers': 12,
        'recent_queries': 28,
        'residential_count': Assessment.objects.filter(property_type='residential').count(),
        'commercial_count': Assessment.objects.filter(property_type='commercial').count(),
        'industrial_count': Assessment.objects.filter(property_type='industrial').count(),
    }
    return render(request, 'Nit/gis.html', context)


@login_required
def reports_view(request):
    context = {
        'total_reports': 45,
        'scheduled_reports': 8,
        'export_formats': ['PDF', 'CSV', 'Excel', 'GeoJSON'],
        'residential_count': Assessment.objects.filter(property_type='residential').count(),
        'commercial_count': Assessment.objects.filter(property_type='commercial').count(),
        'industrial_count': Assessment.objects.filter(property_type='industrial').count(),
    }
    return render(request, 'Nit/reports.html', context)


# ============================================
# MAP VIEWS
# ============================================

def map_view(request):
    """Display ALL buildings from ALL corporations on the common map"""
    total_buildings = Building.objects.count()
    active_buildings = Building.objects.filter(is_active=True).count()

    # Get map position from URL parameters
    map_lat = request.GET.get('lat')
    map_lng = request.GET.get('lng')
    map_zoom = request.GET.get('zoom', 12)
    
    try:
        all_buildings = Building.objects.all().select_related('corporation')
        
        # Build GeoJSON features
        features = []
        for building in all_buildings:
            try:
                if building.geometry:
                    if hasattr(building.geometry, 'geojson'):
                        geometry = json.loads(building.geometry.geojson)
                    else:
                        continue
                else:
                    continue
                
                feature = {
                    "type": "Feature",
                    "geometry": geometry,
                    "properties": {
                        "id": building.id,
                        "gis_id": building.gis_id or str(building.id),
                        "building_number": building.building_number or "",
                        "building_name": building.building_name or "",
                        "area": float(building.area) if building.area else 0,
                        "owner_name": building.owner_name or "Unknown",
                        "city": building.city or "New Delhi",
                        "building_type": building.building_type or "residential",
                        "floors": building.floors or 1,
                        "owner_contact": building.owner_contact or "",
                        "state": building.state or "Delhi",
                        "pincode": building.pincode or "",
                        "corporation": building.corporation.name if building.corporation else 'Unknown',
                        "corporation_id": building.corporation.id if building.corporation else None,
                        "ward": getattr(building, 'ward', "") or "",
                    }
                }
                features.append(feature)
            except Exception as e:
                continue
        
        # Build GeoJSON
        geojson_data = {
            "type": "FeatureCollection",
            "features": features
        }
        
        # Calculate stats
        total_features = len(features)
        total_area = all_buildings.aggregate(Sum('area'))['area__sum'] or 0
        
        corporation_stats = []
        for corp in Corporation.objects.all():
            corp_buildings = corp.buildings.all()
            corporation_stats.append({
                'name': corp.name,
                'count': corp_buildings.count(),
                'area': corp_buildings.aggregate(Sum('area'))['area__sum'] or 0
            })
        
        # ✅ FIXED: Use float() for zoom (OpenLayers supports float zoom)
        context = {
            'geojson_data': json.dumps(geojson_data),
            'total_features': total_features,
            'total_area': total_area,
            'total_buildings': total_buildings,
            'active_buildings': active_buildings,
            'corporation_stats': corporation_stats,
            'corporation_count': Corporation.objects.count(),
            'residential_count': all_buildings.filter(building_type='residential').count(),
            'commercial_count': all_buildings.filter(building_type='commercial').count(),
            'industrial_count': all_buildings.filter(building_type='industrial').count(),
            'corporations': Corporation.objects.all(),
            'map_lat': float(map_lat) if map_lat and map_lat != 'None' else 28.6139,
            'map_lng': float(map_lng) if map_lng and map_lng != 'None' else 77.2090,
            'map_zoom': float(map_zoom) if map_zoom else 12,  # ✅ FIXED: Use float()
        }
        
        return render(request, 'map_view.html', context)
        
    except Exception as e:
        logger.error(f"Error in map_view: {str(e)}")
        # ✅ Single except block with ALL variables
        context = {
            'geojson_data': json.dumps({"type": "FeatureCollection", "features": []}),
            'total_features': 0,
            'total_area': 0,
            'total_buildings': total_buildings,
            'active_buildings': active_buildings,
            'corporation_stats': [],
            'corporation_count': 0,
            'residential_count': 0,
            'commercial_count': 0,
            'industrial_count': 0,
            'corporations': Corporation.objects.all(),
            # ✅ FIXED: Use float() for zoom
            'map_lat': float(map_lat) if map_lat and map_lat != 'None' else 28.6139,
            'map_lng': float(map_lng) if map_lng and map_lng != 'None' else 77.2090,
            'map_zoom': float(map_zoom) if map_zoom else 12,  # ✅ FIXED: Use float()
        }
        return render(request, 'map_view.html', context)


@login_required
def buildings_geojson(request, corporation_id=None):
    """API endpoint - Return buildings as GeoJSON in WGS84 for map display"""
    import json
    
    if corporation_id:
        buildings = Building.objects.filter(corporation_id=corporation_id, geometry__isnull=False)
    else:
        buildings = Building.objects.filter(geometry__isnull=False)
    
    features = []
    for building in buildings:
        if not building.geometry:   
            continue
        try:
            # 🔧 Clone and re-label as 3857 because the data is actually stored
            # as EPSG:3857 meters but the column claims SRID=4326
            geom = building.geometry.clone()
            geom.srid = 3857
            
            # Now GeoDjango will do the transform PROPERLY using PROJ
            geom.transform(4326)
            
            geom_json = json.loads(geom.geojson)
            
            features.append({
                'type': 'Feature',
                'geometry': geom_json,
                'properties': {
                    'id': building.id,
                    'gis_id': building.gis_id,
                    'building_number': building.building_number,
                    'building_name': building.building_name,
                    'area': float(building.area) if building.area else 0,
                    'owner_name': building.owner_name,
                    'address': building.address,
                    'city': building.city,
                    'building_type': building.building_type,
                    'floors': building.floors,
                    'year_built': building.year_built,
                    'owner_contact': building.owner_contact,
                    'state': building.state,
                    'pincode': building.pincode,
                    'corporation': building.corporation.name if building.corporation else None,
                    'corporation_id': building.corporation.id if building.corporation else None,
                }
            })
        except Exception as e:
            print(f"Error processing building {building.id}: {e}")
            continue
    
    return JsonResponse({
        'type': 'FeatureCollection',
        'features': features
    })
    
    
def get_default_context():
    """Get default context with all buildings"""
    buildings = Building.objects.all()
    return {
        'is_corporation_view': False,
        'total_features': buildings.count(),
        'total_area': buildings.aggregate(Sum('area'))['area__sum'] or 0,
        'residential_count': buildings.filter(building_type='residential').count(),
        'commercial_count': buildings.filter(building_type='commercial').count(),
        'industrial_count': buildings.filter(building_type='industrial').count(),
        'total_owners': buildings.values('owner_name').distinct().count(),
    }
from django.http import JsonResponse
from django.db.models import Max
from .models import Building

def get_next_gis_id(request):
    """Get the next available GIS ID in sequential order"""
    try:
        # Get the maximum GIS ID from existing buildings
        # Assuming GIS_ID is stored as an integer or string that can be converted
        max_id = Building.objects.aggregate(Max('gis_id'))['gis_id__max']
        
        if max_id:
            # If it's a number, increment it
            try:
                next_id = int(max_id) + 1
            except (ValueError, TypeError):
                # If it's a string, try to extract number
                import re
                numbers = re.findall(r'\d+', str(max_id))
                if numbers:
                    next_id = int(numbers[-1]) + 1
                else:
                    next_id = 1001
        else:
            next_id = 1000  # Starting number
        
        return JsonResponse({
            'next_id': str(next_id),
            'success': True
        })
    except Exception as e:
        return JsonResponse({
            'next_id': 'B-' + str(int(time.time())),
            'success': False,
            'error': str(e)
        })

# ============================================
# ADMIN DASHBOARD
# ============================================

@admin_required
def admin_dashboard(request):
    corporations = CBE.objects.all()
    datas = Data.objects.all()
    
    datalist = []
    for data in datas:
        mis_count = 0
        pointdata_count = 0
        connected_count = 0
        road_names = []
        
        if data.mis:
            with connection.cursor() as cursor:
                cursor.execute(f"SELECT COUNT(*) FROM `{data.mis}`")
                mis_count = cursor.fetchone()[0]
                cursor.execute(f"SELECT DISTINCT road_name FROM `{data.mis}`")
                road_names = [row[0] for row in cursor.fetchall() if row[0]]
        
        if data.pointdata:
            with connection.cursor() as cursor:
                cursor.execute(f"SELECT COUNT(*) FROM `{data.pointdata}`")
                pointdata_count = cursor.fetchone()[0]
        
        if data.mis and data.pointdata:
            with connection.cursor() as cursor:
                cursor.execute(f"""
                    SELECT COUNT(*) FROM `{data.pointdata}` 
                    WHERE assessment IN (SELECT assessment FROM `{data.mis}`)
                """)
                connected_count = cursor.fetchone()[0]
        
        datalist.append({
            'id': data.id,
            'ward': data.ward,
            'zone': data.zone,
            'corporation': data.corporation_name,
            'miscount': mis_count,
            'pointdatacount': pointdata_count,
            'connected': connected_count,
            'road_name': road_names
        })
    
    context = {
        'corporations': corporations,
        'datas': datalist,
        'total_surveyors': Surveyor.objects.count(),
        'total_assessments': Assessment.objects.count(),
        'total_wards': Ward.objects.count(),
        'pending_assessments': Assessment.objects.filter(status='pending').count(),
        'completed_assessments': Assessment.objects.filter(status='completed').count(),
        'verified_assessments': Assessment.objects.filter(status='verified').count(),
        'recent_assessments': Assessment.objects.order_by('-created_at')[:10],
        'recent_surveyors': Surveyor.objects.order_by('-created_at')[:5],
        'residential_count': Assessment.objects.filter(property_type='residential').count(),
        'commercial_count': Assessment.objects.filter(property_type='commercial').count(),
        'industrial_count': Assessment.objects.filter(property_type='industrial').count(),
    }
    return render(request, 'Nit/admin/dashboard.html', context)


# ============================================
# ADMIN REPORTS & EXPORT
# ============================================

@admin_required
def admin_reports(request):
    context = {
        'total_assessments': Assessment.objects.count(),
        'total_buildings': BuildingData.objects.count(),
        'total_roads': Road.objects.count(),
        'total_points': PointData.objects.count(),
        'total_polygons': PolygonFeature.objects.count(),
        'surveyors_count': Surveyor.objects.count(),
        'wards_count': Ward.objects.count(),
        'assessments_by_type': Assessment.objects.values('property_type').annotate(count=Count('id')),
        'assessments_by_status': Assessment.objects.values('status').annotate(count=Count('id')),
        'residential_count': Assessment.objects.filter(property_type='residential').count(),
        'commercial_count': Assessment.objects.filter(property_type='commercial').count(),
        'industrial_count': Assessment.objects.filter(property_type='industrial').count(),
    }
    return render(request, 'Nit/admin/reports.html', context)


@admin_required
def admin_export(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="assessments_export.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['GIS ID', 'Owner', 'Address', 'Property Type', 'Area (sq m)', 'Status', 'Created At'])
    
    for assessment in Assessment.objects.all():
        writer.writerow([
            assessment.gis_id,
            assessment.owner_name,
            assessment.address,
            assessment.get_property_type_display(),
            assessment.area_sq_m,
            assessment.status,
            assessment.created_at.strftime('%Y-%m-%d %H:%M')
        ])
    
    return response


# ============================================
# SURVEYOR MANAGEMENT
# ============================================

@admin_required
def surveyors_list(request):
    surveyors = Surveyor.objects.select_related('user', 'data').all().order_by('-id')
    datas = Data.objects.all()
    paginator = Paginator(surveyors, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'surveyors': page_obj,
        'datas': datas,
        'total_surveyors': surveyors.count(),
        'residential_count': Assessment.objects.filter(property_type='residential').count(),
        'commercial_count': Assessment.objects.filter(property_type='commercial').count(),
        'industrial_count': Assessment.objects.filter(property_type='industrial').count(),
    }
    return render(request, 'Nit/admin/surveyors_list.html', context)


@admin_required
def store_surveyor(request):
    if request.method == 'GET':
        datas = Data.objects.all()
        return render(request, 'Nit/admin/surveyor_create.html', {'datas': datas})
    
    if request.method == 'POST':
        try:
            name = request.POST.get('name', '').strip()
            email = request.POST.get('email', '').strip()
            mobile = request.POST.get('mobile', '').strip()
            password = request.POST.get('password', '')
            confirm_password = request.POST.get('confirm_password', '')
            is_active = request.POST.get('is_active', 'on') == 'on'
            
            errors = {}
            
            if not name:
                errors['name'] = 'Name is required'
            
            if not email:
                errors['email'] = 'Email is required'
            elif User.objects.filter(email=email).exists():
                errors['email'] = 'Email already exists'
            
            if not mobile:
                errors['mobile'] = 'Mobile number is required'
            
            if not password:
                errors['password'] = 'Password is required'
            elif len(password) < 6:
                errors['password'] = 'Password must be at least 6 characters'
            
            if password != confirm_password:
                errors['confirm_password'] = 'Passwords do not match'
            
            if errors:
                return JsonResponse({'success': False, 'errors': errors}, status=422)
            
            user = User.objects.create_user(
                username=email,
                email=email,
                password=password
            )
            user.first_name = name
            user.save()
            
            UserProfile.objects.create(
                user=user,
                role='surveyor',
                phone=mobile
            )
            
            surveyor = Surveyor.objects.create(
                user=user,
                employee_id=f"SURV-{user.id}",
                mobile=mobile,
                is_active=is_active
            )
            
            return JsonResponse({
                'success': True,
                'message': f'Surveyor {name} created successfully!',
                'surveyor': {
                    'id': surveyor.id,
                    'name': name,
                    'email': email,
                    'mobile': mobile,
                    'is_active': is_active,
                    'created_at': surveyor.created_at.strftime('%Y-%m-%d %H:%M')
                }
            }, status=201)
            
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@admin_required
def surveyor_update(request, id):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        surveyor = get_object_or_404(Surveyor, id=id)
        
        name = request.POST.get('name')
        email = request.POST.get('email')
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        is_active = request.POST.get('is_active', 'on') == 'on'
        
        surveyor.user.username = email
        surveyor.user.email = email
        surveyor.user.first_name = name
        surveyor.user.save()
        
        profile = surveyor.user.profile
        profile.phone = mobile
        profile.save()
        
        surveyor.mobile = mobile
        surveyor.is_active = is_active
        
        if password:
            surveyor.user.set_password(password)
            surveyor.user.save()
        
        surveyor.save()
        
        messages.success(request, 'Surveyor updated successfully!')
        return redirect('admin_surveyors')
        
    except Exception as e:
        messages.error(request, f'Error: {str(e)}')
        return redirect('admin_surveyors')


@admin_required
def surveyor_destroy(request, id):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        surveyor = get_object_or_404(Surveyor, id=id)
        user = surveyor.user
        surveyor.delete()
        user.delete()
        return JsonResponse({'message': 'Surveyor deleted successfully!'}, status=200)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# ============================================
# CBE MANAGEMENT
# ============================================

@admin_required
def cbe_list(request):
    corporations = CBE.objects.all()
    context = {
        'corporations': corporations,
        'residential_count': Assessment.objects.filter(property_type='residential').count(),
        'commercial_count': Assessment.objects.filter(property_type='commercial').count(),
        'industrial_count': Assessment.objects.filter(property_type='industrial').count(),
    }
    return render(request, 'Nit/admin/cbe.html', context)


@admin_required
def cbe_store(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    name = request.POST.get('name')
    email = request.POST.get('email')
    password = request.POST.get('password')
    
    if CBE.objects.filter(email=email).exists():
        return JsonResponse({'errors': {'email': 'Email already exists'}}, status=422)
    
    CBE.objects.create(
        name=name,
        email=email,
        password=password,
        code=name.upper()[:10]
    )
    
    corporations = CBE.objects.all().values('id', 'name', 'email')
    return JsonResponse({
        'data': 'Corporation stored successfully!',
        'corporations': list(corporations)
    }, status=200)


@admin_required
def cbe_update(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    corporation_id = request.POST.get('id')
    corporation = get_object_or_404(CBE, id=corporation_id)
    
    corporation.name = request.POST.get('name')
    corporation.email = request.POST.get('email')
    if request.POST.get('password'):
        corporation.password = request.POST.get('password')
    corporation.save()
    
    corporations = CBE.objects.all().values('id', 'name', 'email')
    return JsonResponse({
        'data': 'Corporation updated successfully!',
        'corporations': list(corporations)
    }, status=200)


@admin_required
def cbe_destroy(request, id):
    corporation = get_object_or_404(CBE, id=id)
    corporation.delete()
    
    corporations = CBE.objects.all().values('id', 'name', 'email')
    return JsonResponse({
        'data': 'Corporation deleted successfully.',
        'corporations': list(corporations)
    }, status=200)


# ============================================
# DATA STORE
# ============================================

@admin_required
def data_store(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    corporation_id = request.POST.get('corporation')
    zone = request.POST.get('zone')
    ward = request.POST.get('ward')
    mis_file = request.FILES.get('mis')
    image_file = request.FILES.get('image')
    
    if not all([corporation_id, zone, ward, mis_file, image_file]):
        return JsonResponse({'errors': 'All fields are required'}, status=422)
    
    corporation = CBE.objects.filter(id=corporation_id).first()
    if not corporation:
        return JsonResponse({'error': 'Corporation not found'}, status=422)
    
    data = Data.objects.create(
        corporation=corporation,
        corporation_name=corporation.name,
        ward=ward,
        zone=zone,
        extend_left=request.POST.get('extend-left', 'false') == 'true',
        extend_right=request.POST.get('extend-right', 'false') == 'true',
        extend_top=request.POST.get('extend-top', 'false') == 'true',
        extend_bottom=request.POST.get('extend-bottom', 'false') == 'true',
    )
    
    create_dynamic_tables(data)
    import_mis_excel(mis_file, data.mis)
    
    if image_file:
        image_path = f'corporations/{corporation.name}/{zone}/{ward}/image_{int(timezone.now().timestamp())}.{image_file.name.split(".")[-1]}'
        path = default_storage.save(image_path, ContentFile(image_file.read()))
        data.image = path
        data.save()
    
    for geo_type in ['point', 'line', 'polygon']:
        geo_file = request.FILES.get(geo_type)
        if geo_file:
            process_geojson(geo_file, data, geo_type)
    
    return JsonResponse({
        'message': 'Success',
        'data': 'Data added successfully',
        'data_id': data.id
    })


def process_geojson(geo_file, data, geo_type):
    """Process GeoJSON file and create Building objects"""
    from django.contrib.gis.geos import GEOSGeometry
    
    try:
        content = json.loads(geo_file.read().decode('utf-8'))
        features = content.get('features', [])
        
        if not features:
            return
        
        for i, feature in enumerate(features):
            try:
                geometry = feature.get('geometry', {})
                properties = feature.get('properties', {})
                
                if not geometry:
                    continue
                
                if geometry['type'] == 'MultiPolygon':
                    geom = GEOSGeometry(json.dumps({
                        'type': 'Polygon',
                        'coordinates': geometry['coordinates'][0]
                    }), srid=3857)
                else:
                    geom = GEOSGeometry(json.dumps(geometry), srid=3857)
                    geom.transform(4326)
                
                gis_id = properties.get('GIS_ID') or f"B-{str(i).zfill(4)}"
                
                Building.objects.create(
                    gis_id=gis_id,
                    building_number=f"B-{str(i).zfill(4)}",
                    building_name=properties.get('name', f"Building {gis_id}"),
                    geometry=geom,
                    area=float(properties.get('sqft', 0)),
                    building_type='residential',
                    floors=1,
                    owner_name='Unknown'
                )
                
            except Exception as e:
                print(f"Error processing feature {i}: {e}")
                continue
                
    except Exception as e:
        print(f"Error processing GeoJSON: {e}")


# ============================================
# SURVEYOR GIS DRAWING FUNCTIONS
# ============================================

@csrf_exempt
@surveyor_required
def add_polygon_feature(request):
    """Add a new polygon feature"""
    try:
        surveyor = request.user.surveyor_profile
        data = surveyor.data
        
        if not data:
            return JsonResponse({'error': 'No data assigned to surveyor'}, status=404)
        
        coordinates = json.loads(request.POST.get('coordinates', '[]'))
        
        if not coordinates:
            return JsonResponse({'error': 'Coordinates are required'}, status=400)
        
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT MAX(gisid) FROM `{data.polygon}`")
            max_gisid = cursor.fetchone()[0] or 0
            new_gisid = max_gisid + 1
            
            cursor.execute(f"""
                INSERT INTO `{data.polygon}` (gisid, coordinates, type, created_at, updated_at)
                VALUES (%s, %s, %s, NOW(), NOW())
            """, [new_gisid, json.dumps(coordinates), 'Polygon'])
            
            midpoint = calculate_data_midpoint(coordinates)
            
            cursor.execute(f"""
                INSERT INTO `{data.point}` (gisid, coordinates, type, created_at, updated_at)
                VALUES (%s, %s, %s, NOW(), NOW())
            """, [new_gisid, json.dumps(midpoint), 'Point'])
        
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT * FROM `{data.polygon}`")
            polygons = cursor.fetchall()
            cursor.execute(f"SELECT * FROM `{data.point}`")
            points = cursor.fetchall()
        
        return JsonResponse({
            'success': True,
            'message': 'Feature added successfully.',
            'polygons': polygons,
            'points': points,
            'gisid': new_gisid
        }, status=200)
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@surveyor_required
def add_line_feature(request):
    """Add a new line feature"""
    try:
        surveyor = request.user.surveyor_profile
        data = surveyor.data
        
        if not data:
            return JsonResponse({'error': 'No data assigned to surveyor'}, status=404)
        
        coordinates = json.loads(request.POST.get('coordinates', '[]'))
        road_name = request.POST.get('road_name', '')
        
        if not coordinates:
            return JsonResponse({'error': 'Coordinates are required'}, status=400)
        
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT MAX(gisid) FROM `{data.line}`")
            max_gisid = cursor.fetchone()[0] or 0
            new_gisid = max_gisid + 1
            
            cursor.execute(f"""
                INSERT INTO `{data.line}` (gisid, coordinates, type, road_name, created_at, updated_at)
                VALUES (%s, %s, %s, %s, NOW(), NOW())
            """, [new_gisid, json.dumps(coordinates), 'MultiLineString', road_name])
        
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT * FROM `{data.polygon}`")
            polygons = cursor.fetchall()
            cursor.execute(f"SELECT * FROM `{data.point}`")
            points = cursor.fetchall()
            cursor.execute(f"SELECT * FROM `{data.line}`")
            lines = cursor.fetchall()
        
        return JsonResponse({
            'success': True,
            'message': 'Line feature added successfully.',
            'polygons': polygons,
            'points': points,
            'lines': lines,
            'gisid': new_gisid
        }, status=200)
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@surveyor_required
def merge_polygon(request):
    """Merge two polygons"""
    try:
        surveyor = request.user.surveyor_profile
        data = surveyor.data
        
        if not data:
            return JsonResponse({'error': 'No data assigned to surveyor'}, status=404)
        
        first_gisid = request.POST.get('firstmerge')
        second_gisid = request.POST.get('secondmerge')
        
        if not first_gisid or not second_gisid:
            return JsonResponse({'error': 'Both GIS IDs are required'}, status=400)
        
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT gisid, coordinates FROM `{data.polygon}` WHERE gisid = %s", [first_gisid])
            first_polygon = cursor.fetchone()
            
            cursor.execute(f"SELECT gisid, coordinates FROM `{data.polygon}` WHERE gisid = %s", [second_gisid])
            second_polygon = cursor.fetchone()
            
            if not first_polygon or not second_polygon:
                return JsonResponse({'error': 'One or both polygons not found'}, status=404)
            
            first_coords = json.loads(first_polygon[1])
            second_coords = json.loads(second_polygon[1])
            
            if isinstance(first_coords[0][0], list):
                merged_coords = first_coords + second_coords
            else:
                merged_coords = [first_coords[0]] + [second_coords[0]]
            
            cursor.execute(f"""
                UPDATE `{data.polygon}` 
                SET coordinates = %s, updated_at = NOW()
                WHERE gisid = %s
            """, [json.dumps(merged_coords), first_gisid])
            
            cursor.execute(f"""
                UPDATE `{data.pointdata}` 
                SET point_gisid = %s 
                WHERE point_gisid = %s
            """, [first_gisid, second_gisid])
            
            cursor.execute(f"DELETE FROM `{data.polygon}` WHERE gisid = %s", [second_gisid])
            cursor.execute(f"DELETE FROM `{data.point}` WHERE gisid = %s", [second_gisid])
        
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT * FROM `{data.polygon}`")
            polygons = cursor.fetchall()
            cursor.execute(f"SELECT * FROM `{data.point}`")
            points = cursor.fetchall()
        
        return JsonResponse({
            'success': True,
            'message': 'Polygons merged successfully.',
            'polygons': polygons,
            'points': points
        }, status=200)
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@surveyor_required
def delete_polygon_feature(request):
    """Delete a polygon feature"""
    try:
        surveyor = request.user.surveyor_profile
        data = surveyor.data
        
        if not data:
            return JsonResponse({'error': 'No data assigned to surveyor'}, status=404)
        
        gisid = request.POST.get('gisid')
        
        if not gisid:
            return JsonResponse({'error': 'GIS ID is required'}, status=400)
        
        with connection.cursor() as cursor:
            cursor.execute(f"""
                SELECT worker_name FROM `{data.pointdata}` 
                WHERE point_gisid = %s 
                AND worker_name != %s
                LIMIT 1
            """, [gisid, surveyor.user.username])
            
            other_worker = cursor.fetchone()
            
            if other_worker:
                return JsonResponse({
                    'error': 'Data found. Please contact the team.',
                    'name': other_worker[0]
                }, status=403)
            
            cursor.execute(f"DELETE FROM `{data.point}` WHERE gisid = %s", [gisid])
            cursor.execute(f"DELETE FROM `{data.polygon}` WHERE gisid = %s", [gisid])
            cursor.execute(f"DELETE FROM `{data.polygondata}` WHERE gisid = %s", [gisid])
        
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT * FROM `{data.polygon}`")
            polygons = cursor.fetchall()
            cursor.execute(f"SELECT * FROM `{data.point}`")
            points = cursor.fetchall()
        
        return JsonResponse({
            'success': True,
            'message': 'Feature deleted successfully.',
            'polygons': polygons,
            'points': points
        }, status=200)
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@surveyor_required
def update_road_name(request):
    """Update road name for a line feature"""
    try:
        surveyor = request.user.surveyor_profile
        data = surveyor.data
        
        if not data:
            return JsonResponse({'error': 'No data assigned to surveyor'}, status=404)
        
        line_gisid = request.POST.get('linegisid')
        road_name = request.POST.get('roadname')
        
        if not line_gisid or not road_name:
            return JsonResponse({'error': 'GIS ID and road name are required'}, status=400)
        
        with connection.cursor() as cursor:
            cursor.execute(f"""
                UPDATE `{data.line}` 
                SET road_name = %s, updated_at = NOW()
                WHERE gisid = %s
            """, [road_name, line_gisid])
            
            cursor.execute(f"SELECT * FROM `{data.line}`")
            lines = cursor.fetchall()
        
        return JsonResponse({
            'success': True,
            'message': 'Road name updated successfully!',
            'lines': lines
        }, status=200)
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@surveyor_required
def split_polygon(request):
    """Split a polygon"""
    try:
        surveyor = request.user.surveyor_profile
        data = surveyor.data
        
        if not data:
            return JsonResponse({'error': 'No data assigned to surveyor'}, status=404)
        
        original_gisid = request.POST.get('original_gisid')
        new_gisid = request.POST.get('new_gisid')
        coordinates = json.loads(request.POST.get('coordinates', '[]'))
        
        if not original_gisid or not new_gisid or not coordinates:
            return JsonResponse({'error': 'Missing required fields'}, status=400)
        
        with connection.cursor() as cursor:
            cursor.execute(f"""
                INSERT INTO `{data.polygon}` (gisid, coordinates, type, created_at, updated_at)
                VALUES (%s, %s, %s, NOW(), NOW())
            """, [new_gisid, json.dumps(coordinates), 'Polygon'])
            
            midpoint = calculate_data_midpoint(coordinates)
            cursor.execute(f"""
                INSERT INTO `{data.point}` (gisid, coordinates, type, created_at, updated_at)
                VALUES (%s, %s, %s, NOW(), NOW())
            """, [new_gisid, json.dumps(midpoint), 'Point'])
            
            cursor.execute(f"""
                UPDATE `{data.polygon}` 
                SET coordinates = %s, updated_at = NOW()
                WHERE gisid = %s
            """, [json.dumps(coordinates), original_gisid])
        
        return JsonResponse({
            'success': True,
            'message': 'Polygon split successfully.'
        }, status=200)
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@surveyor_required
def get_gis_features(request):
    """Get all GIS features for the surveyor's data"""
    try:
        surveyor = request.user.surveyor_profile
        data = surveyor.data
        
        if not data:
            return JsonResponse({'error': 'No data assigned to surveyor'}, status=404)
        
        result = {
            'data_id': data.id,
            'ward': data.ward,
            'zone': data.zone,
            'corporation': data.corporation_name,
            'polygons': [],
            'points': [],
            'lines': []
        }
        
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT id, gisid, coordinates, type FROM `{data.polygon}`")
            for row in cursor.fetchall():
                try:
                    coords = json.loads(row[2]) if row[2] else []
                except:
                    coords = []
                result['polygons'].append({
                    'id': row[0],
                    'gisid': row[1],
                    'coordinates': coords,
                    'type': row[3]
                })
            
            cursor.execute(f"SELECT id, gisid, coordinates, type FROM `{data.point}`")
            for row in cursor.fetchall():
                try:
                    coords = json.loads(row[2]) if row[2] else []
                except:
                    coords = []
                result['points'].append({
                    'id': row[0],
                    'gisid': row[1],
                    'coordinates': coords,
                    'type': row[3]
                })
            
            cursor.execute(f"SELECT id, gisid, coordinates, type, road_name FROM `{data.line}`")
            for row in cursor.fetchall():
                try:
                    coords = json.loads(row[2]) if row[2] else []
                except:
                    coords = []
                result['lines'].append({
                    'id': row[0],
                    'gisid': row[1],
                    'coordinates': coords,
                    'type': row[3],
                    'road_name': row[4] or ''
                })
        
        return JsonResponse(result, status=200)
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# ============================================
# HELPER FUNCTIONS
# ============================================

def calculate_data_midpoint(coordinates):
    """Calculate midpoint of polygon coordinates"""
    try:
        if not coordinates or not isinstance(coordinates, list) or len(coordinates) == 0:
            return [0, 0]
        
        if isinstance(coordinates[0], list) and len(coordinates[0]) > 0:
            if isinstance(coordinates[0][0], list):
                points = coordinates[0]
            else:
                points = coordinates
        else:
            points = coordinates
        
        total_points = len(points)
        if total_points == 0:
            return [0, 0]
        
        mid_lat = sum(p[0] for p in points) / total_points
        mid_lng = sum(p[1] for p in points) / total_points
        
        return [mid_lat, mid_lng]
    except Exception:
        return [0, 0]


def calculate_polygon_area_in_sqft(coordinates):
    """Calculate polygon area in square feet"""
    try:
        if not coordinates or not isinstance(coordinates, list) or len(coordinates) == 0:
            return 0
        
        if isinstance(coordinates[0], list) and len(coordinates[0]) > 0:
            if isinstance(coordinates[0][0], list):
                if len(coordinates[0][0]) == 2:
                    points = coordinates[0]
                else:
                    points = coordinates[0][0]
            else:
                points = coordinates[0]
        else:
            points = coordinates
        
        num_points = len(points)
        if num_points < 3:
            return 0
        
        area = 0
        for i in range(num_points):
            try:
                x = float(points[i][0])
                y = float(points[i][1])
                next_i = (i + 1) % num_points
                x_next = float(points[next_i][0])
                y_next = float(points[next_i][1])
                area += (x * y_next) - (y * x_next)
            except (ValueError, IndexError, TypeError):
                continue
        
        area = abs(area) / 2
        return area * 10.7639
    except Exception:
        return 0


# ============================================
# ADMIN GIS VIEWS
# ============================================

@admin_required
def admin_gis_features(request):
    """Admin view to manage GIS features"""
    data_id = request.GET.get('data_id')
    data = None
    polygons = []
    points = []
    lines = []
    
    if data_id:
        data = Data.objects.filter(id=data_id).first()
        if data:
            with connection.cursor() as cursor:
                cursor.execute(f"SELECT * FROM `{data.polygon}`")
                polygons = cursor.fetchall()
                cursor.execute(f"SELECT * FROM `{data.point}`")
                points = cursor.fetchall()
                cursor.execute(f"SELECT * FROM `{data.line}`")
                lines = cursor.fetchall()
    
    context = {
        'data_list': Data.objects.all(),
        'selected_data': data,
        'polygons': polygons,
        'points': points,
        'lines': lines,
        'residential_count': Assessment.objects.filter(property_type='residential').count(),
        'commercial_count': Assessment.objects.filter(property_type='commercial').count(),
        'industrial_count': Assessment.objects.filter(property_type='industrial').count(),
    }
    return render(request, 'Nit/admin/gis_features.html', context)


@admin_required
def admin_get_gis_data(request):
    """Admin API to get GIS data for a specific data ID"""
    data_id = request.GET.get('data_id')
    
    if not data_id:
        return JsonResponse({'error': 'Data ID is required'}, status=400)
    
    data = Data.objects.filter(id=data_id).first()
    if not data:
        return JsonResponse({'error': 'Data not found'}, status=404)
    
    result = {
        'data_id': data.id,
        'ward': data.ward,
        'zone': data.zone,
        'corporation': data.corporation_name,
    }
    
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT id, gisid, coordinates, type FROM `{data.polygon}`")
        result['polygons'] = [{'id': r[0], 'gisid': r[1], 'coordinates': json.loads(r[2]), 'type': r[3]} for r in cursor.fetchall()]
        
        cursor.execute(f"SELECT id, gisid, coordinates, type FROM `{data.point}`")
        result['points'] = [{'id': r[0], 'gisid': r[1], 'coordinates': json.loads(r[2]), 'type': r[3]} for r in cursor.fetchall()]
        
        cursor.execute(f"SELECT id, gisid, coordinates, type, road_name FROM `{data.line}`")
        result['lines'] = [{'id': r[0], 'gisid': r[1], 'coordinates': json.loads(r[2]), 'type': r[3], 'road_name': r[4]} for r in cursor.fetchall()]
    
    return JsonResponse(result)


# ============================================
# EXPORT FUNCTIONS
# ============================================

@admin_required
def usage_variation_export(request, data_id):
    data = get_object_or_404(Data, id=data_id)
    if not data.mis or not data.pointdata:
        return JsonResponse({'error': 'Invalid table names'}, status=400)
    results = usage_variations(data)
    export = UsageVariationExport(results)
    return export.to_excel()


@admin_required
def area_variation_export(request, data_id):
    data = get_object_or_404(Data, id=data_id)
    if not data.mis or not data.pointdata or not data.polygon:
        return JsonResponse({'error': 'Invalid table names'}, status=400)
    results = area_variations(data)
    export = AreaVariationExport(results)
    return export.to_excel()


@admin_required
def usage_and_area_variation_export(request, data_id):
    try:
        data = get_object_or_404(Data, id=data_id)
        if not data.mis or not data.pointdata or not data.polygon:
            return JsonResponse({'error': 'Invalid table names'}, status=400)
        export = UsageAndAreaVariationExport(data)
        zip_path = export.export_all()
        if zip_path and os.path.exists(zip_path):
            return FileResponse(open(zip_path, 'rb'), as_attachment=True, filename='usage_area_variations.zip')
        else:
            return JsonResponse({'error': 'Could not create zip file'}, status=500)
    except Exception as e:
        return JsonResponse({'error': f'An error occurred: {str(e)}'}, status=500)


@admin_required
def polygon_download(request, data_id):
    data = get_object_or_404(Data, id=data_id)
    if not data.polygon:
        return JsonResponse({'error': 'Polygon table not found'}, status=404)
    
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT id, gisid, coordinates FROM `{data.polygon}`")
        polygons = cursor.fetchall()
    
    features = []
    for poly in polygons:
        try:
            coordinates = json.loads(poly[2])
            features.append({
                'type': 'Feature',
                'properties': {'OBJECTID': poly[0], 'GIS_ID': poly[1]},
                'geometry': {'type': 'Polygon', 'coordinates': coordinates}
            })
        except json.JSONDecodeError:
            continue
    
    geojson = {
        'type': 'FeatureCollection',
        'name': 'qGISGEOJSON',
        'crs': {'type': 'name', 'properties': {'name': 'urn:ogc:def:crs:EPSG::3857'}},
        'features': features
    }
    
    response = JsonResponse(geojson)
    response['Content-Disposition'] = 'attachment; filename="polygons.geojson"'
    response['Content-Type'] = 'application/geo+json'
    return response


@admin_required
def point_download(request, data_id):
    data = get_object_or_404(Data, id=data_id)
    if not data.point:
        return JsonResponse({'error': 'Point table not found'}, status=404)
    
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT id, gisid, coordinates FROM `{data.point}`")
        points = cursor.fetchall()
    
    pointdata_all = {}
    if data.pointdata:
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT point_gisid, * FROM `{data.pointdata}`")
            columns = [desc[0] for desc in cursor.description]
            for row in cursor.fetchall():
                gisid = row[0]
                if gisid not in pointdata_all:
                    pointdata_all[gisid] = []
                pointdata_all[gisid].append(dict(zip(columns, row)))
    
    features = []
    for point in points:
        try:
            coordinates = json.loads(point[2])
            pointdata_list = pointdata_all.get(point[1], [])
            for pd in pointdata_list:
                properties = pd.copy()
                properties['OBJECTID'] = point[0]
                properties['GIS_ID'] = point[1]
                features.append({
                    'type': 'Feature',
                    'properties': properties,
                    'geometry': {'type': 'Point', 'coordinates': coordinates}
                })
        except json.JSONDecodeError:
            continue
    
    geojson = {
        'type': 'FeatureCollection',
        'name': 'qGISGEOJSON',
        'crs': {'type': 'name', 'properties': {'name': 'urn:ogc:def:crs:EPSG::3857'}},
        'features': features
    }
    
    response = JsonResponse(geojson)
    response['Content-Disposition'] = f'attachment; filename="{data.point}.geojson"'
    response['Content-Type'] = 'application/geo+json'
    return response


@admin_required
def road_download(request, data_id):
    data = get_object_or_404(Data, id=data_id)
    if not data.line:
        return JsonResponse({'error': 'Line table not found'}, status=404)
    
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT id, gisid, coordinates, road_name FROM `{data.line}`")
        roads = cursor.fetchall()
    
    features = []
    for road in roads:
        try:
            coordinates = json.loads(road[2])
            features.append({
                'type': 'Feature',
                'properties': {'OBJECTID': road[0], 'GIS_ID': road[1], 'NAME': road[3] if len(road) > 3 else None},
                'geometry': {'type': 'LineString', 'coordinates': coordinates}
            })
        except json.JSONDecodeError:
            continue
    
    geojson = {
        'type': 'FeatureCollection',
        'name': 'qGISGEOJSON',
        'crs': {'type': 'name', 'properties': {'name': 'urn:ogc:def:crs:EPSG::3857'}},
        'features': features
    }
    
    response = JsonResponse(geojson)
    response['Content-Disposition'] = f'attachment; filename="{data.line}.geojson"'
    response['Content-Type'] = 'application/geo+json'
    return response


@admin_required
def download_streetwise(request, data_id):
    data = get_object_or_404(Data, id=data_id)
    if not data.mis:
        return JsonResponse({'error': 'MIS table not found'}, status=404)
    
    import pandas as pd
    
    with connection.cursor() as cursor:
        cursor.execute(f"""
            SELECT road_name, old_door_no, new_door_no, assessment, old_assessment, 
                   owner_name, phone, building_usage 
            FROM `{data.mis}` 
            ORDER BY old_door_no
        """)
        mis_data = cursor.fetchall()
    
    road_groups = {}
    for row in mis_data:
        road_name = row[0] or 'Unknown'
        if road_name not in road_groups:
            road_groups[road_name] = []
        road_groups[road_name].append({
            'road_name': row[0],
            'old_door_no': row[1],
            'new_door_no': row[2],
            'assessment': row[3],
            'old_assessment': row[4],
            'owner_name': row[5],
            'phone': row[6],
            'building_usage': row[7],
        })
    
    export_dir = os.path.join('media', 'streetwise_exports')
    os.makedirs(export_dir, exist_ok=True)
    
    for road_name, data_list in road_groups.items():
        sanitized_name = ''.join(c for c in road_name if c.isalnum() or c in ' _-')
        filepath = os.path.join(export_dir, f"{sanitized_name}.xlsx")
        df = pd.DataFrame(data_list)
        df.to_excel(filepath, index=False)
    
    zip_path = os.path.join('media', 'streetwise_exports.zip')
    create_zip_archive(export_dir, zip_path)
    
    return FileResponse(
        open(zip_path, 'rb'),
        as_attachment=True,
        filename='streetwise_exports.zip'
    )


@admin_required
def download_missing_bill(request, data_id):
    data = get_object_or_404(Data, id=data_id)
    export = MissingBillExport(data)
    return export.to_excel()


@admin_required
def surveyors_count_export(request, data_id):
    data = get_object_or_404(Data, id=data_id)
    surveyors = Surveyor.objects.filter(data_id=data_id)
    
    if not surveyors:
        return JsonResponse({'message': 'No surveyors found.'}, status=404)
    
    if not data.pointdata:
        return JsonResponse({'message': f'Table not found: {data.pointdata}'}, status=404)
    
    results = []
    for surveyor in surveyors:
        with connection.cursor() as cursor:
            cursor.execute(f"""
                SELECT COUNT(*) FROM `{data.pointdata}` WHERE worker_name = %s
            """, [surveyor.user.username])
            surveyed_count = cursor.fetchone()[0]
            
            cursor.execute(f"""
                SELECT COUNT(*) FROM `{data.pointdata}` 
                WHERE worker_name = %s 
                AND assessment IN (SELECT assessment FROM `{data.mis}`)
            """, [surveyor.user.username])
            connected_count = cursor.fetchone()[0]
        
        results.append({
            'surveyor': surveyor.user.username,
            'surveyed_count': surveyed_count,
            'connected_count': connected_count,
            'not_connected_count': surveyed_count - connected_count,
        })
    
    export = SurveyorsExport(results)
    return export.to_excel()


@admin_required
def download_point_data(request, data_id):
    data = get_object_or_404(Data, id=data_id)
    if not data.pointdata:
        return JsonResponse({'error': 'Pointdata table not found'}, status=404)
    
    with connection.cursor() as cursor:
        cursor.execute(f"""
            SELECT pd.*, polyd.road_name 
            FROM `{data.pointdata}` pd
            JOIN `{data.polygondata}` polyd ON polyd.gisid = pd.point_gisid
        """)
        columns = [desc[0] for desc in cursor.description]
        pointdata = [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    export = AssessmentDetailsExport(pointdata, data.ward)
    return export.to_excel()


@admin_required
def download_building_data(request, data_id):
    data = get_object_or_404(Data, id=data_id)
    if not data.polygondata:
        return JsonResponse({'error': 'Buildingdata table not found'}, status=404)
    
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT * FROM `{data.polygondata}`")
        columns = [desc[0] for desc in cursor.description]
        buildingdata = [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    export = BuildingDetailsExport(buildingdata, data.ward)
    return export.to_excel()


# ============================================
# SEARCH FUNCTIONS
# ============================================

@admin_required
def search_gisid(request):
    gisid = request.GET.get('sgisid')
    data_id = request.GET.get('id')
    
    if not gisid or not data_id:
        return render(request, 'Nit/admin/editassessment.html', {
            'pointData': [],
            'data_id': data_id,
            'error': 'GIS ID and Data ID are required'
        })
    
    data = Data.objects.filter(id=data_id).first()
    if not data:
        return render(request, 'Nit/admin/editassessment.html', {
            'pointData': [],
            'data_id': data_id,
            'error': 'No data found'
        })
    
    if not data.pointdata:
        return render(request, 'Nit/admin/editassessment.html', {
            'pointData': [],
            'data_id': data_id,
            'error': 'Invalid point data table'
        })
    
    with connection.cursor() as cursor:
        cursor.execute(f"""
            SELECT * FROM `{data.pointdata}` 
            WHERE point_gisid = %s OR assessment = %s
        """, [gisid, gisid])
        columns = [desc[0] for desc in cursor.description]
        point_data = [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    for pd in point_data:
        pd['val'] = data.id
    
    return render(request, 'Nit/admin/editassessment.html', {
        'pointData': point_data,
        'dataId': data_id
    })


def api_building_search(request):
    """API endpoint to search for buildings by GIS ID with location data"""
    from django.http import JsonResponse
    from django.contrib.gis.geos import Point
    from .models import Building
    import json
    
    gis_id = request.GET.get('gis_id')
    
    if not gis_id:
        return JsonResponse({'error': 'gis_id parameter is required'}, status=400)
    
    try:
        buildings = Building.objects.filter(gis_id__icontains=gis_id)
        
        results = []
        for building in buildings:
            result = {
                'id': building.id,
                'gis_id': building.gis_id,
                'building_number': building.building_number,
                'building_name': building.building_name,
                'owner_name': building.owner_name,
                'area': float(building.area) if building.area else 0,
                'building_type': building.building_type,
                'address': building.address,
                'city': building.city,
                'state': building.state,
                'ward': getattr(building, 'ward', '') or '',
                'corporation': building.corporation.name if building.corporation else None,
                'is_active': building.is_active,
                'geometry': None  # Will be populated if available
            }
            
            # ✅ Get geometry for zooming
            if building.geometry:
                try:
                    geom_json = json.loads(building.geometry.geojson)
                    if geom_json['type'] == 'Point':
                        result['geometry'] = geom_json
                    elif geom_json['type'] == 'Polygon':
                        # Get centroid for zooming
                        coords = geom_json['coordinates'][0]
                        center_lat = sum(p[1] for p in coords) / len(coords)
                        center_lng = sum(p[0] for p in coords) / len(coords)
                        result['geometry'] = {
                            'type': 'Point',
                            'coordinates': [center_lng, center_lat]
                        }
                    elif geom_json['type'] == 'MultiPolygon':
                        # Get centroid of first polygon
                        coords = geom_json['coordinates'][0][0]
                        center_lat = sum(p[1] for p in coords) / len(coords)
                        center_lng = sum(p[0] for p in coords) / len(coords)
                        result['geometry'] = {
                            'type': 'Point',
                            'coordinates': [center_lng, center_lat]
                        }
                except Exception as e:
                    print(f"Error parsing geometry: {e}")
            
            results.append(result)
        
        return JsonResponse({
            'count': len(results),
            'results': results
        }, status=200)
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
@admin_required
def search_building_gisid(request):
    gisid = request.GET.get('sgisid')
    data_id = request.GET.get('id')
    
    if not gisid or not data_id:
        return render(request, 'Nit/admin/editbuilding.html', {
            'polygonData': [],
            'data_id': data_id,
            'error': 'GIS ID and Data ID are required'
        })
    
    data = Data.objects.filter(id=data_id).first()
    if not data:
        return render(request, 'Nit/admin/editbuilding.html', {
            'polygonData': [],
            'data_id': data_id,
            'error': 'No data found'
        })
    
    if not data.polygondata:
        return render(request, 'Nit/admin/editbuilding.html', {
            'polygonData': [],
            'data_id': data_id,
            'error': 'Invalid building data table'
        })
    
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT * FROM `{data.polygondata}` WHERE gisid = %s", [gisid])
        columns = [desc[0] for desc in cursor.description]
        polygon_data = [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    for pd in polygon_data:
        pd['val'] = data.id
    
    return render(request, 'Nit/admin/editbuilding.html', {
        'polygonData': polygon_data,
        'dataId': data_id
    })


# ============================================
# UPDATE FUNCTIONS
# ============================================

@admin_required
def update_building_data(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    data_id = request.POST.get('data', {}).get('val')
    record_id = request.POST.get('id')
    
    if not data_id or not record_id:
        return JsonResponse({'error': 'Missing required fields'}, status=422)
    
    data = Data.objects.filter(id=data_id).first()
    if not data or not data.polygondata:
        return JsonResponse({'error': 'Data not found'}, status=404)
    
    updated_data = request.POST.dict()
    updated_data.pop('id', None)
    updated_data.pop('data[val]', None)
    
    set_clause = []
    values = []
    for key, value in updated_data.items():
        if key.startswith('data[') and key.endswith(']'):
            field = key[5:-1]
            if field not in ['val', 'created_at']:
                set_clause.append(f"`{field}` = %s")
                values.append(value)
    
    if not set_clause:
        return JsonResponse({'error': 'No fields to update'}, status=422)
    
    values.append(record_id)
    
    with connection.cursor() as cursor:
        cursor.execute(f"""
            UPDATE `{data.polygondata}` 
            SET {', '.join(set_clause)}, updated_at = NOW() 
            WHERE id = %s
        """, values)
    
    return JsonResponse({'message': 'Data updated successfully'}, status=200)


@admin_required
def delete_building_data(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    data_id = request.POST.get('data', {}).get('val')
    record_id = request.POST.get('id')
    
    if not data_id or not record_id:
        return JsonResponse({'error': 'Missing required fields'}, status=422)
    
    data = Data.objects.filter(id=data_id).first()
    if not data or not data.polygondata:
        return JsonResponse({'error': 'Data not found'}, status=404)
    
    with connection.cursor() as cursor:
        cursor.execute(f"DELETE FROM `{data.polygondata}` WHERE id = %s", [record_id])
    
    return JsonResponse({'message': 'Data deleted successfully'}, status=200)


@admin_required
def update_assessment_data(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    data_id = request.POST.get('data', {}).get('val')
    record_id = request.POST.get('id')
    
    if not data_id or not record_id:
        return JsonResponse({'error': 'Missing required fields'}, status=422)
    
    data = Data.objects.filter(id=data_id).first()
    if not data or not data.pointdata:
        return JsonResponse({'error': 'Data not found'}, status=404)
    
    updated_data = request.POST.dict()
    updated_data.pop('id', None)
    updated_data.pop('data[val]', None)
    
    set_clause = []
    values = []
    for key, value in updated_data.items():
        if key.startswith('data[') and key.endswith(']'):
            field = key[5:-1]
            if field not in ['val', 'created_at']:
                set_clause.append(f"`{field}` = %s")
                values.append(value)
    
    if not set_clause:
        return JsonResponse({'error': 'No fields to update'}, status=422)
    
    values.append(record_id)
    
    with connection.cursor() as cursor:
        cursor.execute(f"""
            UPDATE `{data.pointdata}` 
            SET {', '.join(set_clause)}, updated_at = NOW() 
            WHERE id = %s
        """, values)
    
    return JsonResponse({'message': 'Data updated successfully'}, status=200)


@admin_required
def delete_assessment_data(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    data_id = request.POST.get('data', {}).get('val')
    record_id = request.POST.get('id')
    
    if not data_id or not record_id:
        return JsonResponse({'error': 'Missing required fields'}, status=422)
    
    data = Data.objects.filter(id=data_id).first()
    if not data or not data.pointdata:
        return JsonResponse({'error': 'Data not found'}, status=404)
    
    with connection.cursor() as cursor:
        cursor.execute(f"DELETE FROM `{data.pointdata}` WHERE id = %s", [record_id])
    
    return JsonResponse({'message': 'Data deleted successfully'}, status=200)


# ============================================
# GIS OPERATIONS
# ============================================

@admin_required
def replace_gisid(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    data_id = request.POST.get('id')
    old_gisid = request.POST.get('dgisid1')
    new_gisid = request.POST.get('dgisid2')
    
    if not all([data_id, old_gisid, new_gisid]):
        return JsonResponse({'error': 'Missing required fields'}, status=422)
    
    data = Data.objects.filter(id=data_id).first()
    if not data:
        return JsonResponse({'error': 'Data not found'}, status=404)
    
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT COUNT(*) FROM `{data.polygon}` WHERE gisid IN (%s, %s)", [old_gisid, new_gisid])
        count = cursor.fetchone()[0]
        
        if count < 2:
            return JsonResponse({'error': True, 'message': 'Data Not Found'}, status=404)
        
        cursor.execute(f"UPDATE `{data.polygon}` SET gisid = %s WHERE gisid = %s", [new_gisid, old_gisid])
        
        if data.point:
            cursor.execute(f"UPDATE `{data.point}` SET gisid = %s WHERE gisid = %s", [new_gisid, old_gisid])
        
        cursor.execute(f"""
            DELETE FROM `{data.polygon}` 
            WHERE gisid = %s 
            ORDER BY id ASC 
            LIMIT 1
        """, [new_gisid])
        
        if data.point:
            cursor.execute(f"""
                DELETE FROM `{data.point}` 
                WHERE gisid = %s 
                ORDER BY id ASC 
                LIMIT 1
            """, [new_gisid])
    
    return JsonResponse({'success': True, 'message': 'GIS ID replaced successfully.'})


# ============================================
# SURVEYOR DASHBOARD
# ============================================

@surveyor_required
def surveyor_dashboard(request):
    context = {
        'total_assessments': Assessment.objects.filter(surveyor=request.user).count(),
        'pending_assessments': Assessment.objects.filter(surveyor=request.user, status='pending').count(),
        'completed_assessments': Assessment.objects.filter(surveyor=request.user, status='completed').count(),
        'verified_assessments': Assessment.objects.filter(surveyor=request.user, status='verified').count(),
        'recent_assessments': Assessment.objects.filter(surveyor=request.user).order_by('-created_at')[:10],
        'today_attendance': Attendance.objects.filter(surveyor=request.user, date=timezone.now().date()).first(),
        'residential_count': Assessment.objects.filter(property_type='residential').count(),
        'commercial_count': Assessment.objects.filter(property_type='commercial').count(),
        'industrial_count': Assessment.objects.filter(property_type='industrial').count(),
    }
    return render(request, 'Nit/surveyor/dashboard.html', context)


@surveyor_required
def find_gisid(request):
    if request.method == 'POST':
        gis_id = request.POST.get('gis_id')
        assessment = Assessment.objects.filter(gis_id=gis_id).first()
        if assessment:
            return JsonResponse({
                'exists': True,
                'data': {
                    'id': assessment.id,
                    'gis_id': assessment.gis_id,
                    'owner_name': assessment.owner_name,
                    'address': assessment.address,
                    'property_type': assessment.get_property_type_display(),
                    'status': assessment.status,
                }
            })
        return JsonResponse({'exists': False})
    return render(request, 'Nit/surveyor/find_gisid.html')


@surveyor_required
def upload_assessment_data(request):
    wards = Ward.objects.filter(is_active=True)
    context = {
        'wards': wards,
        'total_assessments': Assessment.objects.filter(surveyor=request.user).count(),
        'pending_count': Assessment.objects.filter(surveyor=request.user, status='pending').count(),
        'completed_count': Assessment.objects.filter(surveyor=request.user, status='completed').count(),
        'verified_count': Assessment.objects.filter(surveyor=request.user, status='verified').count(),
        'residential_count': Assessment.objects.filter(property_type='residential').count(),
        'commercial_count': Assessment.objects.filter(property_type='commercial').count(),
        'industrial_count': Assessment.objects.filter(property_type='industrial').count(),
    }
    
    if request.method == 'POST':
        try:
            assessment = Assessment.objects.create(
                gis_id=request.POST.get('gis_id'),
                surveyor=request.user,
                owner_name=request.POST.get('owner_name'),
                address=request.POST.get('address'),
                property_type=request.POST.get('property_type', 'residential'),
                area_sq_m=request.POST.get('area_sq_m', 0),
                latitude=request.POST.get('latitude') or None,
                longitude=request.POST.get('longitude') or None,
                status='pending',
                created_by=request.user,
                ward_id=request.POST.get('ward_id') or None
            )
            messages.success(request, 'Assessment uploaded successfully!')
            return redirect('surveyor_dashboard')
        except Exception as e:
            messages.error(request, f'Error: {str(e)}')
    
    return render(request, 'Nit/surveyor/upload_data.html', context)


@surveyor_required
def attendance_in(request):
    if request.method == 'POST':
        today = timezone.now().date()
        attendance, created = Attendance.objects.get_or_create(
            surveyor=request.user,
            date=today,
            defaults={'status': 'present'}
        )
        if attendance.check_in_time:
            messages.warning(request, 'You have already checked in today.')
        else:
            attendance.check_in_time = timezone.now()
            attendance.check_in_lat = request.POST.get('latitude')
            attendance.check_in_lng = request.POST.get('longitude')
            attendance.save()
            messages.success(request, 'Attendance marked IN successfully!')
        return redirect('surveyor_dashboard')
    return JsonResponse({'error': 'Invalid request'}, status=400)


@surveyor_required
def attendance_out(request):
    if request.method == 'POST':
        today = timezone.now().date()
        attendance = Attendance.objects.filter(surveyor=request.user, date=today).first()
        if not attendance:
            messages.error(request, 'You have not checked in today.')
        elif attendance.check_out_time:
            messages.warning(request, 'You have already checked out today.')
        else:
            attendance.check_out_time = timezone.now()
            attendance.check_out_lat = request.POST.get('latitude')
            attendance.check_out_lng = request.POST.get('longitude')
            attendance.save()
            messages.success(request, 'Attendance marked OUT successfully!')
        return redirect('surveyor_dashboard')
    return JsonResponse({'error': 'Invalid request'}, status=400)


# ============================================
# CBE & TAX COLLECTOR DASHBOARD
# ============================================

@cbe_required
def cbe_dashboard(request):
    context = {
        'total_cbes': CBE.objects.count(),
        'active_cbes': CBE.objects.filter(is_active=True).count(),
        'recent_cbes': CBE.objects.order_by('-created_at')[:10],
        'residential_count': Assessment.objects.filter(property_type='residential').count(),
        'commercial_count': Assessment.objects.filter(property_type='commercial').count(),
        'industrial_count': Assessment.objects.filter(property_type='industrial').count(),
    }
    return render(request, 'Nit/cbe/dashboard.html', context)


@taxcollector_required
def taxcollector_dashboard(request):
    context = {
        'total_tax_collected': Assessment.objects.filter(tax_paid=True).aggregate(Sum('tax_amount'))['tax_amount__sum'] or 0,
        'total_pending_tax': Assessment.objects.filter(tax_paid=False).aggregate(Sum('tax_amount'))['tax_amount__sum'] or 0,
        'total_assessments': Assessment.objects.count(),
        'paid_assessments': Assessment.objects.filter(tax_paid=True).count(),
        'pending_assessments': Assessment.objects.filter(tax_paid=False).count(),
        'residential_count': Assessment.objects.filter(property_type='residential').count(),
        'commercial_count': Assessment.objects.filter(property_type='commercial').count(),
        'industrial_count': Assessment.objects.filter(property_type='industrial').count(),
    }
    return render(request, 'Nit/taxcollector/dashboard.html', context)


# ============================================
# API VIEWS
# ============================================

def api_surveys(request):
    survey_type = request.GET.get('type', '')
    ward_id = request.GET.get('ward', '')
    
    queryset = Assessment.objects.filter(status='verified')
    if survey_type:
        queryset = queryset.filter(property_type=survey_type)
    if ward_id:
        queryset = queryset.filter(ward_id=ward_id)
    
    features = []
    for assessment in queryset[:500]:
        if assessment.latitude and assessment.longitude:
            features.append({
                'type': 'Feature',
                'geometry': {
                    'type': 'Point',
                    'coordinates': [float(assessment.longitude), float(assessment.latitude)]
                },
                'properties': {
                    'id': assessment.gis_id,
                    'type': assessment.get_property_type_display(),
                    'owner': assessment.owner_name,
                    'address': assessment.address,
                    'area': str(assessment.area_sq_m),
                    'status': assessment.status,
                }
            })
    
    return JsonResponse({'type': 'FeatureCollection', 'features': features})


@login_required
def api_property_detail(request, gis_id):
    """API endpoint for property details"""
    assessment = get_object_or_404(Assessment, gis_id=gis_id)
    
    status_colors = {
        'pending': 'warning',
        'completed': 'success',
        'verified': 'info',
        'rejected': 'danger'
    }
    
    data = {
        'gis_id': assessment.gis_id,
        'owner_name': assessment.owner_name,
        'address': assessment.address,
        'property_type': assessment.get_property_type_display(),
        'area_sq_m': str(assessment.area_sq_m),
        'latitude': str(assessment.latitude) if assessment.latitude else None,
        'longitude': str(assessment.longitude) if assessment.longitude else None,
        'status': assessment.status,
        'status_color': status_colors.get(assessment.status, 'secondary'),
        'ward_name': assessment.ward.name if assessment.ward else None,
        'created_at': assessment.created_at.strftime('%Y-%m-%d %H:%M'),
    }
    
    return JsonResponse(data)


def api_wards(request):
    wards = Ward.objects.filter(is_active=True)
    features = []
    for ward in wards:
        features.append({
            'type': 'Feature',
            'geometry': {
                'type': 'Point',
                'coordinates': [float(ward.longitude) if ward.longitude else 0, float(ward.latitude) if ward.latitude else 0]
            },
            'properties': {
                'id': ward.ward_number,
                'name': ward.name,
                'area_ha': str(ward.area_ha) if ward.area_ha else '0',
                'population': ward.population,
            }
        })
    return JsonResponse({'type': 'FeatureCollection', 'features': features})


@login_required
def advanced_search(request):
    """Advanced search for assessments"""
    query = request.GET.get('q', '')
    property_type = request.GET.get('type', '')
    status = request.GET.get('status', '')
    ward_id = request.GET.get('ward', '')
    
    assessments = Assessment.objects.all()
    
    if query:
        assessments = assessments.filter(
            Q(gis_id__icontains=query) |
            Q(owner_name__icontains=query) |
            Q(address__icontains=query)
        )
    
    if property_type:
        assessments = assessments.filter(property_type=property_type)
    
    if status:
        assessments = assessments.filter(status=status)
    
    if ward_id:
        assessments = assessments.filter(ward_id=ward_id)
    
    context = {
        'assessments': assessments,
        'wards': Ward.objects.filter(is_active=True),
        'total_results': assessments.count(),
        'search_query': query,
        'property_type': property_type,
        'status': status,
        'ward_id': ward_id,
        'residential_count': Assessment.objects.filter(property_type='residential').count(),
        'commercial_count': Assessment.objects.filter(property_type='commercial').count(),
        'industrial_count': Assessment.objects.filter(property_type='industrial').count(),
    }
    
    return render(request, 'Nit/advanced_search.html', context)


@admin_required
def bulk_import_assessment(request):
    """Bulk import assessments from Excel/CSV"""
    if request.method == 'POST':
        file = request.FILES.get('file')
        if not file:
            messages.error(request, 'Please select a file')
            return redirect('admin_dashboard')
        
        try:
            import pandas as pd
            df = pd.read_excel(file) if file.name.endswith(('.xlsx', '.xls')) else pd.read_csv(file)
            
            count = 0
            for _, row in df.iterrows():
                Assessment.objects.create(
                    gis_id=row.get('gis_id', f'GIS-{count+1}'),
                    owner_name=row.get('owner_name', 'Unknown'),
                    address=row.get('address', ''),
                    property_type=row.get('property_type', 'residential'),
                    area_sq_m=row.get('area_sq_m', 0),
                    latitude=row.get('latitude', None),
                    longitude=row.get('longitude', None),
                    status='pending',
                    created_by=request.user,
                    ward_id=row.get('ward_id', None)
                )
                count += 1
            
            messages.success(request, f'Successfully imported {count} assessments!')
        except Exception as e:
            messages.error(request, f'Error importing: {str(e)}')
        
        return redirect('admin_dashboard')
    
    context = {
        'wards': Ward.objects.filter(is_active=True),
        'residential_count': Assessment.objects.filter(property_type='residential').count(),
        'commercial_count': Assessment.objects.filter(property_type='commercial').count(),
        'industrial_count': Assessment.objects.filter(property_type='industrial').count(),
    }
    return render(request, 'Nit/admin/bulk_import.html', context)
# Nit/views.py
import os
import json
import math
from django.http import HttpResponse, JsonResponse
from django.conf import settings
from django.shortcuts import render


def drone_tile(request, z, x, y):
    """
    Serve drone image tiles in XYZ format
    """
    # Path to your drone tiles - adjust based on your structure
    # Option 1: If you have pre-generated tiles
    tile_path = os.path.join(settings.MEDIA_ROOT, 'drone_tiles', str(z), str(x), f'{y}.jpg')
    
    # Option 2: If tiles are in static folder
    # tile_path = os.path.join(settings.BASE_DIR, 'static', 'drone_tiles', str(z), str(x), f'{y}.jpg')
    
    # Option 3: If tiles are in a specific app folder
    # tile_path = os.path.join(settings.BASE_DIR, 'Nit', 'static', 'drone_tiles', str(z), str(x), f'{y}.jpg')
    
    if os.path.exists(tile_path):
        with open(tile_path, 'rb') as f:
            return HttpResponse(f.read(), content_type='image/jpeg')
    
    # Return a transparent tile if not found
    return HttpResponse(status=404)

def list_drone_images(request):
    """
    List available drone images with their metadata
    """
    drone_data = []
    
    # Read from your Image folder
    image_folder = os.path.join(settings.MEDIA_ROOT, 'Image')
    
    # If using static folder instead
    # image_folder = os.path.join(settings.BASE_DIR, 'static', 'drone_images')
    
    if os.path.exists(image_folder):
        for filename in os.listdir(image_folder):
            if filename.lower().endswith(('.jpg', '.jpeg', '.png', '.tif')):
                # Get image extents
                extents = get_image_extents(filename)
                
                drone_data.append({
                    'name': filename,
                    'url': f'/media/Image/{filename}',
                    'extents': extents,
                    'polygon': get_polygon_data(filename),
                    'road': get_road_data(filename)
                })
    
    return JsonResponse(drone_data, safe=False)

def get_image_extents(filename):
    """Get image extents from your Image Extents folder"""
    # Try to find extents file
    base_name = os.path.splitext(filename)[0]
    
    # Check for various file extensions
    possible_extensions = ['.geojson', '.json', '.txt']
    extents_folder = os.path.join(settings.MEDIA_ROOT, 'Image Extents')
    
    for ext in possible_extensions:
        extents_file = os.path.join(extents_folder, f'{base_name}{ext}')
        if os.path.exists(extents_file):
            try:
                with open(extents_file, 'r') as f:
                    data = json.load(f)
                    # Try to extract bounds from different formats
                    if 'extents' in data:
                        return data['extents']
                    elif 'bbox' in data:
                        return data['bbox']
                    elif 'coordinates' in data:
                        # Try to get from polygon coordinates
                        coords = data['coordinates'][0]
                        min_lat = min(c[1] for c in coords)
                        max_lat = max(c[1] for c in coords)
                        min_lon = min(c[0] for c in coords)
                        max_lon = max(c[0] for c in coords)
                        return [min_lon, min_lat, max_lon, max_lat]
            except:
                pass
    
    return [0, 0, 0, 0]  # Return default if not found

def get_polygon_data(filename):
    """Get polygon data from your Polygon folder"""
    base_name = os.path.splitext(filename)[0]
    polygon_folder = os.path.join(settings.MEDIA_ROOT, 'Polygon')
    
    possible_extensions = ['.geojson', '.json']
    for ext in possible_extensions:
        polygon_file = os.path.join(polygon_folder, f'{base_name}{ext}')
        if os.path.exists(polygon_file):
            try:
                with open(polygon_file, 'r') as f:
                    return json.load(f)
            except:
                pass
    return None

def get_road_data(filename):
    """Get road data from your Road folder"""
    base_name = os.path.splitext(filename)[0]
    road_folder = os.path.join(settings.MEDIA_ROOT, 'Road')
    
    possible_extensions = ['.geojson', '.json']
    for ext in possible_extensions:
        road_file = os.path.join(road_folder, f'{base_name}{ext}')
        if os.path.exists(road_file):
            try:
                with open(road_file, 'r') as f:
                    return json.load(f)
            except:
                pass
    return None

import os
import json
from django.http import JsonResponse
from django.conf import settings

def check_drone_image(request):
    """
    Check if drone image exists for a ward
    """
    ward = request.GET.get('ward', '')
    
    if not ward:
        return JsonResponse({'exists': False, 'error': 'No ward specified'})
    
    # Try different possible image names
    image_folder = os.path.join(settings.MEDIA_ROOT, 'Image')
    possible_names = [
        f'{ward}.png',
        f'{ward}.jpg',
        f'{ward}.jpeg',
        f'ward_{ward}.png',
        f'ward_{ward}.jpg',
        f'{ward}_drone.png',
        f'{ward}_drone.jpg',
    ]
    
    for image_name in possible_names:
        image_path = os.path.join(image_folder, image_name)
        if os.path.exists(image_path):
            # Found the image!
            base_name = os.path.splitext(image_name)[0]
            
            # Try to get extents
            extents = get_extents_for_image(ward, base_name)
            
            return JsonResponse({
                'exists': True,
                'url': f'/media/Image/{image_name}',
                'ward': ward,
                'image_name': image_name,
                'extents': extents or [78.1536, 11.6446, 78.1736, 11.6646]
            })
    
    # No image found
    return JsonResponse({
        'exists': False,
        'ward': ward,
        'message': f'No drone image found for Ward {ward}'
    })

def get_extents_for_image(ward, base_name):
    """
    Get extents for a ward image from multiple sources
    """
    # Check .pgw file
    pgw_path = os.path.join(settings.MEDIA_ROOT, 'Image', f'{base_name}.pgw')
    if os.path.exists(pgw_path):
        return read_pgw_file(pgw_path, f'{base_name}.png')
    
    # Check GeoJSON file
    geojson_path = os.path.join(settings.MEDIA_ROOT, 'Image Extents', f'{base_name}.geojson')
    if os.path.exists(geojson_path):
        return read_geojson_extents(geojson_path)
    
    # Check ward-specific extents
    ward_geojson = os.path.join(settings.MEDIA_ROOT, 'Image Extents', f'ward_{ward}.geojson')
    if os.path.exists(ward_geojson):
        return read_geojson_extents(ward_geojson)
    
    # Check if there's a generic extents file for the ward
    extents_folder = os.path.join(settings.MEDIA_ROOT, 'Image Extents')
    if os.path.exists(extents_folder):
        for filename in os.listdir(extents_folder):
            if filename.startswith(str(ward)) and filename.endswith('.geojson'):
                return read_geojson_extents(os.path.join(extents_folder, filename))
    
    return None

def read_pgw_file(pgw_path, image_name):
    """Read .pgw world file and calculate image extents"""
    try:
        with open(pgw_path, 'r') as f:
            lines = f.readlines()
            if len(lines) >= 6:
                pixel_x = float(lines[0].strip())
                pixel_y = float(lines[3].strip())
                upper_left_x = float(lines[4].strip())
                upper_left_y = float(lines[5].strip())
                
                # Get image size
                image_path = os.path.join(os.path.dirname(pgw_path), image_name)
                if os.path.exists(image_path):
                    from PIL import Image
                    img = Image.open(image_path)
                    width, height = img.size
                    
                    # Calculate extents
                    min_x = upper_left_x
                    max_x = upper_left_x + (width * pixel_x)
                    min_y = upper_left_y + (height * pixel_y)
                    max_y = upper_left_y
                    
                    return [min_x, min_y, max_x, max_y]
    except Exception as e:
        print(f"Error reading .pgw: {e}")
    
    return None

def read_geojson_extents(geojson_path):
    """Read extents from GeoJSON file"""
    try:
        with open(geojson_path, 'r') as f:
            data = json.load(f)
            
            # Try different possible formats
            if 'extents' in data:
                return data['extents']
            if 'bbox' in data:
                return data['bbox']
            if 'properties' in data and 'extents' in data['properties']:
                return data['properties']['extents']
            if 'geometry' in data and data['geometry']['type'] == 'Polygon':
                coords = data['geometry']['coordinates'][0]
                if coords and len(coords) > 0:
                    min_lon = min(c[0] for c in coords)
                    max_lon = max(c[0] for c in coords)
                    min_lat = min(c[1] for c in coords)
                    max_lat = max(c[1] for c in coords)
                    return [min_lon, min_lat, max_lon, max_lat]
    except Exception as e:
        print(f"Error reading GeoJSON: {e}")
    
    return None
# Nit/views.py
import os
import json
import re
from django.http import JsonResponse, HttpResponse
from django.conf import settings

def get_drone_image(request):
    """
    Get the current drone image info
    This will support future multiple images
    """
    # Look for drone images in the media/Image folder
    image_folder = os.path.join(settings.MEDIA_ROOT, 'Image')
    
    # Find all drone images
    drone_images = []
    
    if os.path.exists(image_folder):
        for filename in os.listdir(image_folder):
            if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.tif')):
                # Check if there's a companion .pgw file
                base_name = os.path.splitext(filename)[0]
                pgw_file = os.path.join(image_folder, base_name + '.pgw')
                
                extents = None
                if os.path.exists(pgw_file):
                    extents = read_pgw_file(pgw_file, filename)
                
                # Check for GeoJSON extents
                if not extents:
                    geojson_file = os.path.join(image_folder.replace('Image', 'Image Extents'), base_name + '.geojson')
                    if os.path.exists(geojson_file):
                        extents = read_geojson_extents(geojson_file)
                
                drone_images.append({
                    'name': filename,
                    'url': f'/media/Image/{filename}',
                    'extents': extents,
                    'altitude': extract_altitude(filename),
                    'date': os.path.getmtime(os.path.join(image_folder, filename))
                })
    
    if drone_images:
        # Return the first image (you can add logic to select specific one)
        return JsonResponse(drone_images[0])
    
    # Return default if no image found
    return JsonResponse({
        'name': 'default',
        'url': '/media/Image/91.png',
        'extents': [78.1536, 11.6446, 78.1736, 11.6646],
        'altitude': 120
    })

def list_drone_images(request):
    """
    List all available drone images
    """
    image_folder = os.path.join(settings.MEDIA_ROOT, 'Image')
    drone_images = []
    
    if os.path.exists(image_folder):
        for filename in os.listdir(image_folder):
            if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.tif')):
                base_name = os.path.splitext(filename)[0]
                
                # Try to get extents from various sources
                extents = None
                
                # Check .pgw file
                pgw_file = os.path.join(image_folder, base_name + '.pgw')
                if os.path.exists(pgw_file):
                    extents = read_pgw_file(pgw_file, filename)
                
                # Check GeoJSON
                if not extents:
                    geojson_file = os.path.join(settings.MEDIA_ROOT, 'Image Extents', base_name + '.geojson')
                    if os.path.exists(geojson_file):
                        extents = read_geojson_extents(geojson_file)
                
                drone_images.append({
                    'name': filename,
                    'url': f'/media/Image/{filename}',
                    'extents': extents,
                    'altitude': extract_altitude(filename)
                })
    
    return JsonResponse(drone_images, safe=False)

def list_wards_with_drone_images(request):
    """
    List all wards that have drone images
    """
    image_folder = os.path.join(settings.MEDIA_ROOT, 'Image')
    wards = []
    
    if os.path.exists(image_folder):
        for filename in os.listdir(image_folder):
            # Extract ward number from filename
            # Supports: 91.png, ward_91.png, 91_drone.png, etc.
            match = re.search(r'(\d+)\.(png|jpg|jpeg|tif)', filename, re.IGNORECASE)
            if match:
                ward_number = match.group(1)
                
                # Check if this ward already exists in list
                existing = next((w for w in wards if w['number'] == ward_number), None)
                
                if existing:
                    existing['image_count'] += 1
                else:
                    # Try to get extents
                    extents = get_extents_for_ward(ward_number)
                    
                    wards.append({
                        'number': ward_number,
                        'has_drone': True,
                        'image_count': 1,
                        'extents': extents,
                        'sample_image': f'/media/Image/{filename}'
                    })
    
    # Sort wards by number
    wards.sort(key=lambda x: int(x['number']))
    
    return JsonResponse(wards, safe=False)

def check_drone_image(request):
    """
    Check if drone image exists for a ward
    """
    ward = request.GET.get('ward', '')
    
    if not ward:
        return JsonResponse({'exists': False, 'error': 'No ward specified'})
    
    image_folder = os.path.join(settings.MEDIA_ROOT, 'Image')
    
    # Try different possible image names
    possible_names = [
        f'{ward}.png',
        f'{ward}.jpg',
        f'{ward}.jpeg',
        f'ward_{ward}.png',
        f'ward_{ward}.jpg',
        f'{ward}_drone.png',
        f'{ward}_drone.jpg',
    ]
    
    for image_name in possible_names:
        image_path = os.path.join(image_folder, image_name)
        if os.path.exists(image_path):
            base_name = os.path.splitext(image_name)[0]
            extents = get_extents_for_ward(ward)
            
            return JsonResponse({
                'exists': True,
                'url': f'/media/Image/{image_name}',
                'ward': ward,
                'image_name': image_name,
                'extents': extents or [78.1536, 11.6446, 78.1736, 11.6646]
            })
    
    return JsonResponse({
        'exists': False,
        'ward': ward,
        'message': f'No drone image found for Ward {ward}'
    })

def get_extents_for_ward(ward_number):
    """
    Get extents for a ward from various sources
    """
    # Check .pgw file
    pgw_path = os.path.join(settings.MEDIA_ROOT, 'Image', f'{ward_number}.pgw')
    if os.path.exists(pgw_path):
        return read_pgw_file(pgw_path, f'{ward_number}.png')
    
    # Check GeoJSON file
    geojson_path = os.path.join(settings.MEDIA_ROOT, 'Image Extents', f'{ward_number}.geojson')
    if os.path.exists(geojson_path):
        return read_geojson_extents(geojson_path)
    
    # Check ward-specific extents
    ward_geojson = os.path.join(settings.MEDIA_ROOT, 'Image Extents', f'ward_{ward_number}.geojson')
    if os.path.exists(ward_geojson):
        return read_geojson_extents(ward_geojson)
    
    # Check if there's any extents file for this ward
    extents_folder = os.path.join(settings.MEDIA_ROOT, 'Image Extents')
    if os.path.exists(extents_folder):
        for filename in os.listdir(extents_folder):
            if filename.startswith(str(ward_number)) and filename.endswith('.geojson'):
                return read_geojson_extents(os.path.join(extents_folder, filename))
    
    return None

def read_pgw_file(pgw_path, image_name):
    """Read .pgw world file and calculate image extents"""
    try:
        with open(pgw_path, 'r') as f:
            lines = f.readlines()
            if len(lines) >= 6:
                pixel_x = float(lines[0].strip())
                pixel_y = float(lines[3].strip())
                upper_left_x = float(lines[4].strip())
                upper_left_y = float(lines[5].strip())
                
                # Get image size
                image_path = os.path.join(os.path.dirname(pgw_path), image_name)
                if os.path.exists(image_path):
                    from PIL import Image
                    img = Image.open(image_path)
                    width, height = img.size
                    
                    # Calculate extents
                    min_x = upper_left_x
                    max_x = upper_left_x + (width * pixel_x)
                    min_y = upper_left_y + (height * pixel_y)
                    max_y = upper_left_y
                    
                    return [min_x, min_y, max_x, max_y]
    except Exception as e:
        print(f"Error reading .pgw: {e}")
    
    return None

def read_geojson_extents(geojson_path):
    """Read extents from GeoJSON file"""
    try:
        with open(geojson_path, 'r') as f:
            data = json.load(f)
            
            if 'extents' in data:
                return data['extents']
            if 'bbox' in data:
                return data['bbox']
            if 'properties' in data and 'extents' in data['properties']:
                return data['properties']['extents']
            if 'geometry' in data and data['geometry']['type'] == 'Polygon':
                coords = data['geometry']['coordinates'][0]
                if coords and len(coords) > 0:
                    min_lon = min(c[0] for c in coords)
                    max_lon = max(c[0] for c in coords)
                    min_lat = min(c[1] for c in coords)
                    max_lat = max(c[1] for c in coords)
                    return [min_lon, min_lat, max_lon, max_lat]
    except Exception as e:
        print(f"Error reading GeoJSON: {e}")
    
    return None

def extract_altitude(filename):
    """Extract altitude from filename or metadata"""
    import re
    match = re.search(r'alt(\d+)', filename, re.IGNORECASE)
    if match:
        return int(match.group(1))
    return 120  # Default altitude

def drone_tile(request, z, x, y):
    """
    Serve drone image tiles in XYZ format
    """
    # Try multiple locations
    possible_paths = [
        os.path.join(settings.MEDIA_ROOT, 'drone_tiles', str(z), str(x), f'{y}.jpg'),
        os.path.join(settings.MEDIA_ROOT, 'drone_tiles', str(z), str(x), f'{y}.png'),
        os.path.join(settings.MEDIA_ROOT, 'Image', '91.png'),
        os.path.join(settings.MEDIA_ROOT, 'image', '91.png'),
    ]
    
    for tile_path in possible_paths:
        if os.path.exists(tile_path):
            try:
                with open(tile_path, 'rb') as f:
                    content_type = 'image/png' if tile_path.endswith('.png') else 'image/jpeg'
                    return HttpResponse(f.read(), content_type=content_type)
            except Exception as e:
                print(f"Error reading {tile_path}: {e}")
                continue
    
    return HttpResponse(status=404)