from .decompile import decompile
from .utility import get_parser


def main():

    parser = get_parser()

    args = parser.parse_args()

    decompile(args)


if __name__ == "__main__":
    main()
