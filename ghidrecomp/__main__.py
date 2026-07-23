from .decompile import decompile
from .parser import get_parser


def main():

    parser = get_parser()

    args = parser.parse_args()

    if bool(args.bin) == bool(args.existing_project):
        parser.error('exactly one of `bin` or `--existing-project` must be provided')
    if args.program_filters and not args.existing_project:
        parser.error('--program-name requires --existing-project')
    if args.force_reanalyze and not args.existing_project:
        parser.error('--force-reanalyze requires --existing-project')

    decompile(args)


if __name__ == "__main__":
    main()
