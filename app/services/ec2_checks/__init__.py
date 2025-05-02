# app/services/ec2_checks/__init__.py
# EC2 recommendation checks package initialization

from .stopped_instance import check_stopped_instance
from .old_generation_instance import check_old_generation_instance
from .reserved_instance import check_reserved_instance_recommendation
from .security_group import check_security_group_recommendations
from .cpu_utilization import check_cpu_utilization
from .ebs_optimization import check_ebs_optimization
from .tag_recommendations import check_tag_recommendations
from .network_performance import check_network_performance
from .backup_recommendations import check_backup_recommendations

__all__ = [
    'check_stopped_instance',
    'check_old_generation_instance',
    'check_reserved_instance_recommendation',
    'check_security_group_recommendations',
    'check_cpu_utilization',
    'check_ebs_optimization',
    'check_tag_recommendations',
    'check_network_performance',
    'check_backup_recommendations'
]