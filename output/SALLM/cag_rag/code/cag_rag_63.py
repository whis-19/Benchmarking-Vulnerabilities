import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Compute an expression tree.')
    parser.add_argument('expression', type=str, help='The expression tree in a suitable format (e.g., a string representation).')
    args = parser.parse_args()

    # TODO: Implement a function to parse the expression string into a TreeNode
    # tree_root = parse_expression_string(args.expression)

    # For now, use the example tree:
    root = TreeNode('+')
    root.left = TreeNode('*')
    root.right = TreeNode('5')
    root.left.left = TreeNode('3')
    root.left.right = TreeNode('2')
    tree_root = root


    result = compute_tree(tree_root)
    print(f"Result: {result}")

