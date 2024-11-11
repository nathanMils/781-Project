from sklearn.tree import DecisionTreeClassifier

import logging

logger = logging.getLogger('model.decision_tree')


# class DecisionTreeClassifier(
#     *,
#     criterion: Literal['gini', 'entropy', 'log_loss'] = "gini",
#     splitter: Literal['best', 'random'] = "best",
#     max_depth: Int | None = None,
#     min_samples_split: float | int = 2,
#     min_samples_leaf: float | int = 1,
#     min_weight_fraction_leaf: Float = 0,
#     max_features: float | int | Literal['auto', 'sqrt', 'log2'] | None = None,
#     random_state: Int | RandomState | None = None,
#     max_leaf_nodes: Int | None = None,
#     min_impurity_decrease: Float = 0,
#     class_weight: Mapping | str | Sequence[Mapping] | None = None,
#     ccp_alpha: float = 0
# )

class DecisionTree:
    def __init__(
            self, 
            criterion='gini',
            splitter='best',
            max_depth=None,
            min_samples_split=2,
            min_samples_leaf=1,
            min_weight_fraction_leaf=0,
            max_features=None,
            random_state=None,
            max_leaf_nodes=None,
            min_impurity_decrease=0,
            class_weight=None,
            ccp_alpha=0
        ):
        logger.info("Creating Decision Tree Classifier")
        self.model = DecisionTreeClassifier(
            criterion=criterion,
            splitter=splitter,
            max_depth=max_depth,
            min_samples_split=min_samples_split,
            min_samples_leaf=min_samples_leaf,
            min_weight_fraction_leaf=min_weight_fraction_leaf,
            max_features=max_features,
            random_state=random_state,
            max_leaf_nodes=max_leaf_nodes,
            min_impurity_decrease=min_impurity_decrease,
            class_weight=class_weight,
            ccp_alpha=ccp_alpha
        )

    def fit(self, X, y):
        self.model.fit(X, y)

    def predict(self, X):
        return self.model.predict(X)

    def predict_proba(self, X):
        return self.model.predict_proba(X)

    def score(self, X, y):
        return self.model.score(X, y)