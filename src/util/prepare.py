import os
import yaml
import shutil

def replace_root_keyword(yaml_files, target_files, project_dir):
    for yaml_file, target_file in zip(yaml_files, target_files):
        # Copy the YAML file to the target location
        shutil.copy(yaml_file, target_file)
        
        # Replace <ROOT> keyword in the copied file
        with open(target_file, 'r') as file:
            data = yaml.safe_load(file)
        
        data_str = yaml.dump(data)
        data_str = data_str.replace('<ROOT>', project_dir)
        
        with open(target_file, 'w') as file:
            file.write(data_str)

def find_project_root(current_path):
    while current_path != os.path.dirname(current_path):
        if 'scripts' in os.listdir(current_path):
            return os.path.dirname(current_path)
        current_path = os.path.dirname(current_path)
    return None

def prepare():
    current_path = os.path.dirname(os.path.abspath(__file__))
    project_root = find_project_root(current_path)
    
    if project_root:
        yaml_files = [
            './scripts/meta/meta_dt_temp.yaml',
            './scripts/meta/meta_xgb_temp.yaml',
            './scripts/meta/meta_lgr_temp.yaml',
        ]
        target_files = [
            './mlruns/models/Decision_Tree/version-1/meta.yaml',
            './mlruns/models/XGBoost/version-1/meta.yaml',
            './mlruns/models/Logistic_Regression/version-1/meta.yaml',
        ]
        replace_root_keyword(yaml_files, target_files, project_root)
    else:
        print("Project root directory not found.")