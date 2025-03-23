import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from dataclasses import dataclass
from typing import List, Dict, Any
from datetime import datetime

@dataclass
class SystemMetrics:
    """Metrics for a single VANET system"""
    system_name: str
    security_score: float
    performance_score: float
    visualization_score: float
    feature_completeness: float
    user_experience: float
    attack_detection_rate: float
    message_delivery_rate: float
    average_latency: float
    resource_usage: float
    scalability_score: float

class VANETComparativeAnalysis:
    """Comparative analysis of different VANET systems"""
    
    def __init__(self):
        self.systems: Dict[str, SystemMetrics] = {}
        self.baseline_metrics = {
            'traditional_vanet': SystemMetrics(
                system_name="Traditional VANET",
                security_score=0.6,
                performance_score=0.7,
                visualization_score=0.5,
                feature_completeness=0.6,
                user_experience=0.4,
                attack_detection_rate=0.5,
                message_delivery_rate=0.7,
                average_latency=0.2,
                resource_usage=0.8,
                scalability_score=0.6
            ),
            'basic_security': SystemMetrics(
                system_name="Basic Security Tool",
                security_score=0.4,
                performance_score=0.8,
                visualization_score=0.3,
                feature_completeness=0.4,
                user_experience=0.5,
                attack_detection_rate=0.3,
                message_delivery_rate=0.8,
                average_latency=0.1,
                resource_usage=0.9,
                scalability_score=0.7
            )
        }
    
    def add_system(self, metrics: SystemMetrics):
        """Add a new system to the comparison"""
        self.systems[metrics.system_name] = metrics
    
    def calculate_overall_score(self, metrics: SystemMetrics) -> float:
        """Calculate overall score for a system"""
        weights = {
            'security_score': 0.25,
            'performance_score': 0.2,
            'visualization_score': 0.15,
            'feature_completeness': 0.15,
            'user_experience': 0.15,
            'attack_detection_rate': 0.1
        }
        
        return sum(
            getattr(metrics, metric) * weight
            for metric, weight in weights.items()
        )
    
    def generate_comparison_report(self) -> Dict[str, Any]:
        """Generate a comprehensive comparison report"""
        report = {
            'systems': {},
            'overall_scores': {},
            'comparative_analysis': {},
            'timestamp': datetime.now().isoformat()
        }
        
        # Add all systems including baselines
        all_systems = {**self.systems, **self.baseline_metrics}
        
        for name, metrics in all_systems.items():
            report['systems'][name] = {
                'security': metrics.security_score,
                'performance': metrics.performance_score,
                'visualization': metrics.visualization_score,
                'features': metrics.feature_completeness,
                'ux': metrics.user_experience,
                'attack_detection': metrics.attack_detection_rate,
                'message_delivery': metrics.message_delivery_rate,
                'latency': metrics.average_latency,
                'resource_usage': metrics.resource_usage,
                'scalability': metrics.scalability_score
            }
            
            report['overall_scores'][name] = self.calculate_overall_score(metrics)
        
        # Calculate comparative advantages
        for name, metrics in self.systems.items():
            advantages = []
            for baseline_name, baseline in self.baseline_metrics.items():
                if metrics.security_score > baseline.security_score:
                    advantages.append(f"Superior security over {baseline_name}")
                if metrics.performance_score > baseline.performance_score:
                    advantages.append(f"Better performance than {baseline_name}")
                if metrics.visualization_score > baseline.visualization_score:
                    advantages.append(f"Enhanced visualization compared to {baseline_name}")
                if metrics.feature_completeness > baseline.feature_completeness:
                    advantages.append(f"More comprehensive features than {baseline_name}")
                if metrics.user_experience > baseline.user_experience:
                    advantages.append(f"Improved user experience over {baseline_name}")
            
            report['comparative_analysis'][name] = advantages
        
        return report
    
    def plot_comparison(self, save_path: str = None):
        """Generate comparison plots"""
        all_systems = {**self.systems, **self.baseline_metrics}
        
        # Create figure with subplots
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('VANET Systems Comparison', fontsize=16)
        
        # Radar chart for main metrics
        metrics = ['security_score', 'performance_score', 'visualization_score', 
                  'feature_completeness', 'user_experience']
        
        angles = np.linspace(0, 2*np.pi, len(metrics), endpoint=False)
        angles = np.concatenate((angles, [angles[0]]))  # close the plot
        
        for name, system in all_systems.items():
            values = [getattr(system, metric) for metric in metrics]
            values = np.concatenate((values, [values[0]]))  # close the plot
            axes[0, 0].plot(angles, values, label=name, marker='o')
        
        axes[0, 0].set_xticks(angles[:-1])
        axes[0, 0].set_xticklabels(metrics)
        axes[0, 0].set_title('Main Metrics Comparison')
        axes[0, 0].legend()
        
        # Bar chart for performance metrics
        perf_metrics = ['attack_detection_rate', 'message_delivery_rate', 
                       'average_latency', 'resource_usage', 'scalability_score']
        
        x = np.arange(len(perf_metrics))
        width = 0.25
        
        for idx, (name, system) in enumerate(all_systems.items()):
            values = [getattr(system, metric) for metric in perf_metrics]
            axes[0, 1].bar(x + idx*width, values, width, label=name)
        
        axes[0, 1].set_xticks(x + width)
        axes[0, 1].set_xticklabels(perf_metrics, rotation=45)
        axes[0, 1].set_title('Performance Metrics')
        axes[0, 1].legend()
        
        # Overall scores comparison
        overall_scores = {
            name: self.calculate_overall_score(system)
            for name, system in all_systems.items()
        }
        
        axes[1, 0].bar(overall_scores.keys(), overall_scores.values())
        axes[1, 0].set_title('Overall System Scores')
        axes[1, 0].tick_params(axis='x', rotation=45)
        
        # Resource usage vs Performance
        for name, system in all_systems.items():
            axes[1, 1].scatter(system.resource_usage, system.performance_score, 
                             label=name, s=100)
        
        axes[1, 1].set_xlabel('Resource Usage')
        axes[1, 1].set_ylabel('Performance Score')
        axes[1, 1].set_title('Resource Usage vs Performance')
        axes[1, 1].legend()
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path)
        else:
            plt.show()
    
    def export_report(self, format: str = 'json', filepath: str = None):
        """Export the comparison report in specified format"""
        report = self.generate_comparison_report()
        
        if format == 'json':
            import json
            if filepath:
                with open(filepath, 'w') as f:
                    json.dump(report, f, indent=4)
            return json.dumps(report, indent=4)
        
        elif format == 'csv':
            import pandas as pd
            df = pd.DataFrame(report['systems']).T
            if filepath:
                df.to_csv(filepath)
            return df.to_csv()
        
        else:
            raise ValueError(f"Unsupported format: {format}") 