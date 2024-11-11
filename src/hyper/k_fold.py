from sklearn.model_selection import StratifiedKFold
import numpy as np

def stratified_k_fold_split(X, y, n_splits=5, random_state=None):
    """
    Perform stratified k-fold split.

    Parameters:
    X : array-like, shape (n_samples, n_features)
        The data to split.
    y : array-like, shape (n_samples,)
        The target variable for supervised learning problems.
    n_splits : int, default=5
        Number of folds. Must be at least 2.
    random_state : int or None, default=None
        Random state for reproducibility.

    Returns:
    List of tuples: (train_index, test_index)
    """
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=random_state)
    splits = list(skf.split(X, y))
    return splits

def get_fold_data(X, y, train_index, test_index):
    """
    Get the training and testing data for a specific fold.

    Parameters:
    X : array-like, shape (n_samples, n_features)
        The data to split.
    y : array-like, shape (n_samples,)
        The target variable for supervised learning problems.
    train_index : array-like
        The training set indices for that fold.
    test_index : array-like
        The testing set indices for that fold.

    Returns:
    X_train, X_test, y_train, y_test : arrays
        The training and testing data and labels for that fold.
    """
    X_train, X_test = X[train_index], X[test_index]
    y_train, y_test = y[train_index], y[test_index]
    return X_train, X_test, y_train, y_test

# Example usage:
if __name__ == "__main__":
    # Example data
    X = np.array([[1, 2], [3, 4], [5, 6], [7, 8], [9, 10], [11, 12]])
    y = np.array([0, 0, 1, 1, 2, 2])

    splits = stratified_k_fold_split(X, y, n_splits=3, random_state=42)
    for fold, (train_index, test_index) in enumerate(splits):
        print(f"Fold {fold + 1}")
        X_train, X_test, y_train, y_test = get_fold_data(X, y, train_index, test_index)
        print("Train Index:", train_index, "Test Index:", test_index)
        print("X_train:", X_train, "X_test:", X_test)
        print("y_train:", y_train, "y_test:", y_test)