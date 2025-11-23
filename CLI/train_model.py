#!/usr/bin/env python3
"""
HashTrace ADVANCED Model Trainer - AUTO MODEL SELECTION
Trains multiple models, selects best performer automatically
"""

import pandas as pd
import numpy as np
import warnings
import joblib
import time
import os
from pathlib import Path
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, classification_report, f1_score
from sklearn.preprocessing import StandardScaler
# from hash_features import extract_hash_features, get_feature_names
from hash_features import advanced_hash_features, get_feature_names  # CHANGED


warnings.filterwarnings('ignore', category=RuntimeWarning, module='numpy')



current_dir = Path(__file__).parent
project_root = current_dir.parent 

class AdvancedHashMLTrainer:
    def __init__(self):
        self.feature_names = get_feature_names()
        self.models = {}
        self.results = {}
        self.best_model = None
        self.best_model_name = None
        
    def load_dataset(self, csv_path):
        """Load and prepare dataset with robust column detection"""
        print("📁 Loading dataset...")
        df = pd.read_csv(csv_path)
        
        print(f"📊 Dataset Info:")
        print(f"   - Total samples: {len(df):,}")
        print(f"   - Columns: {df.columns.tolist()}")
        
        # Auto-detect columns
        hash_col = None
        type_col = None
        
        for col in df.columns:
            col_lower = col.lower()
            if 'hash' in col_lower and not hash_col:
                hash_col = col
            elif ('algorithm' in col_lower or 'type' in col_lower) and not type_col:
                type_col = col
        
        # Use detected columns or fallback
        if hash_col and type_col:
            df = df.rename(columns={hash_col: 'hash', type_col: 'hash_type'})
            print(f"✅ Auto-mapped: {hash_col} -> hash, {type_col} -> hash_type")
        elif len(df.columns) >= 2:
            df = df.rename(columns={df.columns[0]: 'hash', df.columns[1]: 'hash_type'})
            print(f"✅ Fallback mapping: {df.columns[0]} -> hash, {df.columns[1]} -> hash_type")
        else:
            raise ValueError("Cannot detect appropriate columns for hash and algorithm")
        
        # Keep only needed columns
        df = df[['hash', 'hash_type']].dropna()
        
        print(f"📊 Final Dataset:")
        print(f"   - Samples: {len(df):,}")
        print(f"   - Hash types: {df['hash_type'].nunique()}")
        
        type_counts = df['hash_type'].value_counts()
        print(f"   - Distribution: {type_counts.iloc[0]} (max) - {type_counts.iloc[-1]} (min)")
        
        return df
   


    def validate_and_clean_features(self, X):
        """Clean and validate features to remove NaN/inf values with proper dtype"""
            # Convert to numpy array with explicit float64 type
        X_clean = np.array(X, dtype=np.float64)
            
            # Replace NaN and infinity with 0
        X_clean = np.nan_to_num(X_clean, nan=0.0, posinf=0.0, neginf=0.0)
            
            # Ensure all values are finite and convert to float32 for neural network
        X_clean = X_clean.astype(np.float32)
            
            # Check for any remaining issues
        if np.any(np.isnan(X_clean)) or np.any(np.isinf(X_clean)):
            print("⚠️  Warning: Features still contain invalid values after cleaning")
            
        return X_clean


    
    def extract_features(self, df):
        """Extract ADVANCED features from all hashes with visual progress bar"""
        print("🔧 Extracting ADVANCED cryptographic features...")
        
        features_list = []
        valid_indices = []
        total_hashes = len(df)
        
        # Progress tracking variables
        start_time = time.time()
        last_update_time = start_time
        bar_length = 30  # Length of the progress bar
        
        print()  # Empty line for progress bar
        
        for idx, hash_str in enumerate(df['hash']):
            try:
                # USE ADVANCED FEATURE EXTRACTOR
                features_dict = advanced_hash_features(str(hash_str))
                features_vector = [features_dict.get(key, 0) for key in self.feature_names]
                features_list.append(features_vector)
                valid_indices.append(idx)
                
                # Update progress every hash or at intervals for large datasets
                current_time = time.time()
                if current_time - last_update_time >= 0.5 or idx == total_hashes - 1:
                    progress = (idx + 1) / total_hashes
                    elapsed_time = current_time - start_time
                    
                    # Calculate ETA
                    if progress > 0:
                        estimated_total_time = elapsed_time / progress
                        remaining_time = estimated_total_time - elapsed_time
                        eta_str = f"ETA: {remaining_time:.0f}s"
                    else:
                        eta_str = "ETA: Calculating..."
                    
                    # Create visual progress bar
                    filled_length = int(bar_length * progress)
                    bar = '█' * filled_length + '░' * (bar_length - filled_length)
                    percentage = progress * 100
                    
                    # Print progress bar
                    print(f"\r   📊 [{bar}] {percentage:6.2f}% ({idx+1}/{total_hashes}) - {eta_str}", end='', flush=True)
                    last_update_time = current_time
                    
            except Exception as e:
                if len(valid_indices) < 5:
                    print(f"\n⚠️  Error processing hash {idx}: {e}")
                continue
        
        # Clear the progress bar line and print completion message
        print("\r" + " " * 100 + "\r", end='')  # Clear the line
        
        X = np.array(features_list)
        y = df.iloc[valid_indices]['hash_type'].values
        
        # CONVERT BOOLEAN FEATURES TO NUMERIC
        X = self.convert_features_to_numeric(X)
        
        # CLEAN AND VALIDATE FEATURES
        X = self.validate_and_clean_features(X)
        
        total_time = time.time() - start_time
        print(f"✅ ADVANCED Cryptographic Features extracted in {total_time:.2f}s:")
        print(f"   - Successful: {X.shape[0]:,}")
        print(f"   - Failed: {len(df) - X.shape[0]}")
        print(f"   - Features: {X.shape[1]} (bit-level, statistical, encoding)")
        print(f"   - Classes: {len(np.unique(y))}")
        
        return X, y

    def convert_features_to_numeric(self, X):
        """Convert boolean/string features to numeric values"""
        X_numeric = []
        for features in X:
            numeric_features = []
            for value in features:
                if isinstance(value, bool):
                    numeric_features.append(1.0 if value else 0.0)
                elif isinstance(value, (int, float)):
                    numeric_features.append(float(value))
                elif isinstance(value, str):
                    if value.lower() in ['true', 't']:
                        numeric_features.append(1.0)
                    elif value.lower() in ['false', 'f']:
                        numeric_features.append(0.0)
                    else:
                        try:
                            numeric_features.append(float(value))
                        except:
                            numeric_features.append(0.0)
                else:
                    numeric_features.append(0.0)
            X_numeric.append(numeric_features)
        return np.array(X_numeric)
    
    def initialize_models(self):
        """Initialize multiple ML models for comparison"""
        print("🤖 Initializing models for training...")
        
        self.models = {
            'RandomForest': RandomForestClassifier(
                n_estimators=150,
                max_depth=25,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1,
                class_weight='balanced'
            ),
            'LogisticRegression': LogisticRegression(
                C=1.0,
                solver='lbfgs',
                max_iter=1000,
                # multi_class='multinomial',
                random_state=42,
                class_weight='balanced'
            ),
            'DecisionTree': DecisionTreeClassifier(
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                class_weight='balanced'
            )
        }
        
        print(f"✅ {len(self.models)} models initialized")
        return list(self.models.keys())
    
    def train_models(self, X_train, X_test, y_train, y_test):
        """Train all models and evaluate performance"""
        print("\n🚀 Training all models...")
        print("=" * 60)
        
        self.results = {}
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        for name, model in self.models.items():
            print(f"\n🎯 Training {name}...")
            start_time = time.time()
            
            try:
                # Scale data for models that need it
                if name in ['SVM', 'NeuralNetwork', 'LogisticRegression']:
                    X_tr = X_train_scaled
                    X_te = X_test_scaled
                else:
                    X_tr = X_train
                    X_te = X_test
                
                # Train model
                model.fit(X_tr, y_train)
                
                # Predictions
                predict_start = time.time()
                train_pred = model.predict(X_tr)
                test_pred = model.predict(X_te)
                prediction_time = time.time() - predict_start
                
                training_time = time.time() - start_time

                # Calculate comprehensive metrics
                train_acc = accuracy_score(y_train, train_pred)
                test_acc = accuracy_score(y_test, test_pred)
                
                # Get detailed classification report
                report = classification_report(y_test, test_pred, output_dict=True)
                
                # Calculate weighted precision, recall, f1
                weighted_metrics = report['weighted avg']
                precision = weighted_metrics['precision']
                recall = weighted_metrics['recall']
                f1 = weighted_metrics['f1-score']
                
                # Cross-validation score
                cv_scores = cross_val_score(model, X_tr, y_train, cv=3, scoring='accuracy')
                cv_mean = np.mean(cv_scores)
                cv_std = np.std(cv_scores)
                
                # Store comprehensive results
                self.results[name] = {
                    'model': model,
                    'train_accuracy': train_acc,
                    'test_accuracy': test_acc,
                    'precision': precision,
                    'recall': recall,
                    'f1_score': f1,
                    'cv_score': cv_mean,
                    'cv_std': cv_std,
                    'training_time': training_time,
                    'prediction_time': prediction_time,
                    'model_size': self._estimate_model_size(model),  # Add this method
                    'scaler': scaler if name in ['SVM', 'NeuralNetwork', 'LogisticRegression'] else None,
                    'detailed_report': report
                }
                
                print(f"   ✅ {name}:")
                print(f"      📈 Accuracy: {test_acc:.4f}")
                print(f"      🎯 Precision: {precision:.4f}")
                print(f"      🔍 Recall: {recall:.4f}")
                print(f"      ⚡ F1-Score: {f1:.4f}")
                print(f"      ⏱️  Train: {training_time:.2f}s, Predict: {prediction_time:.4f}s")
                
            except Exception as e:
                print(f"   ❌ {name} failed: {e}")
                continue

        return self.results

    def _estimate_model_size(self, model):
        """Estimate model size in memory (approximate)"""
        try:
            # Use joblib to estimate size
            import io
            buffer = io.BytesIO()
            joblib.dump(model, buffer)
            size_mb = len(buffer.getvalue()) / (1024 * 1024)  # Convert to MB
            return size_mb
        except:
            return 0.0
    
    def select_best_model(self):
        """Automatically select the best model based on multiple criteria"""
        print("\n🏆 Selecting best model...")
        
        if not self.results:
            raise ValueError("No models trained successfully")
        
        # Score models based on multiple criteria
        model_scores = {}
        
        for name, result in self.results.items():
            # Primary: Test accuracy (60% weight)
            accuracy_score = result['test_accuracy'] * 0.6
            
            # Secondary: F1 score (20% weight)
            f1_score = result['f1_score'] * 0.2
            
            # Tertiary: Cross-validation consistency (10% weight)
            cv_score = result['cv_score'] * 0.1
            
            # Quaternary: Training speed (10% weight) - faster is better
            time_score = (1 / (result['training_time'] + 0.1)) * 0.1
            
            total_score = accuracy_score + f1_score + cv_score + time_score
            model_scores[name] = total_score
        
        # Select best model
        self.best_model_name = max(model_scores, key=model_scores.get)
        self.best_model = self.results[self.best_model_name]
        
        print(f"✅ Best Model Selected: {self.best_model_name}")
        print(f"   🎯 Overall Score: {model_scores[self.best_model_name]:.4f}")
        print(f"   📊 Test Accuracy: {self.best_model['test_accuracy']:.4f}")
        print(f"   ⏱️  Training Time: {self.best_model['training_time']:.2f}s")
        
        # Show comparison table
        print("\n📊 Model Comparison:")
        print("Model               | Test Acc | F1 Score | CV Score | Time(s) | Score")
        print("-" * 65)
        for name, score in sorted(model_scores.items(), key=lambda x: x[1], reverse=True):
            result = self.results[name]
            print(f"{name:18} | {result['test_accuracy']:8.4f} | {result['f1_score']:8.4f} | "
                  f"{result['cv_score']:8.4f} | {result['training_time']:7.2f} | {score:.4f}")
        
        return self.best_model_name, self.best_model
    
    def save_best_model(self, filename="hashtrace_ml_advanced.pkl"):
        """Save the best model with comprehensive metadata"""
        if not self.best_model:
            raise ValueError("No best model selected")
        
        model_data = {
            'model': self.best_model['model'],
            'feature_names': self.feature_names,
            'classes': self.best_model['model'].classes_,
            'scaler': self.best_model.get('scaler'),
            'model_name': self.best_model_name,
            'performance': {
                'test_accuracy': self.best_model['test_accuracy'],
                'f1_score': self.best_model['f1_score'],
                'training_time': self.best_model['training_time']
            },
            'all_models_results': self.results,
            'timestamp': datetime.now().isoformat(),
            'version': '2.0.0'
        }
        
        joblib.dump(model_data, filename)
        
        print(f"\n💾 Best model saved as: {filename}")
        print(f"   - Model: {self.best_model_name}")
        print(f"   - Accuracy: {self.best_model['test_accuracy']:.4f}")
        print(f"   - Features: {len(self.feature_names)}")
        print(f"   - Classes: {len(model_data['classes'])}")
        print(f"   - Timestamp: {model_data['timestamp']}")
        
        return filename
    
    def train(self, csv_path, output_model="hashtrace_ml_advanced.pkl"):
        """Complete advanced training pipeline"""
        start_time = time.time()
        
        # Load and prepare data
        df = self.load_dataset(csv_path)
        X, y = self.extract_features(df)
        
        if len(X) == 0:
            raise ValueError("No valid hashes found for training")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"\n🎯 Training Setup:")
        print(f"   - Training samples: {X_train.shape[0]:,}")
        print(f"   - Test samples: {X_test.shape[0]:,}")
        print(f"   - Features: {X_train.shape[1]}")
        print(f"   - Classes: {len(np.unique(y_train))}")
        
        # Initialize and train models
        self.initialize_models()
        self.train_models(X_train, X_test, y_train, y_test)
        
        # Select and save best model
        best_name, best_result = self.select_best_model()
        model_path = self.save_best_model(output_model)
        
        total_time = time.time() - start_time
        
        print(f"\n🎉 ADVANCED TRAINING COMPLETED!")
        print(f"   ⏱️  Total time: {total_time:.2f} seconds")
        print(f"   🏆 Best model: {best_name}")
        print(f"   📈 Best accuracy: {best_result['test_accuracy']:.4f}")
        print(f"   💾 Saved as: {output_model}")
        
        return best_result['test_accuracy'], best_name

def main():
    """Main function for CLI usage"""
    print("🚀 HashTrace ADVANCED Model Trainer")
    print("=" * 60)
    print("🤖 Trains multiple models and selects the best automatically")
    print("=" * 60)
    
    # Configurable paths
    dataset_path = project_root / "Data" / "balanced_hash_dataset.csv" 
    output_model = project_root / "Models" / "hashtrace_ml_advanced.pkl"

    # Convert to string for compatibility
    dataset_path = str(dataset_path)
    output_model = str(output_model)

    
    trainer = AdvancedHashMLTrainer()
    
    try:
        accuracy, best_model = trainer.train(dataset_path, output_model)
        
        print(f"\n✅ Ready for both CLI and GUI usage!")
        print(f"   - Use: python hashtrace_ml.py <hash>")
        print(f"   - Or: python hashtrace_ml.py --gui")
        print(f"   - Best model ({best_model}) will be used automatically")
        
    except Exception as e:
        print(f"❌ Training failed: {e}")
        print("\n💡 Troubleshooting:")
        print("   1. Check dataset file exists and format")
        print("   2. Ensure columns include hash and algorithm names")
        print("   3. Verify sufficient training data")
        print("   4. Check available memory for large datasets")

if __name__ == "__main__":
    main()
