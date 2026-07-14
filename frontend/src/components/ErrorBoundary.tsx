import { Component, type ErrorInfo, type ReactNode } from "react";

interface ErrorBoundaryProps {
    children: ReactNode;
    fallback?: ReactNode;
}

interface ErrorBoundaryState {
    hasError: boolean;
    error: Error | null;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
    constructor(props: ErrorBoundaryProps) {
        super(props);
        this.state = { hasError: false, error: null };
    }

    static getDerivedStateFromError(error: Error): ErrorBoundaryState {
        return { hasError: true, error };
    }

    componentDidCatch(error: Error, info: ErrorInfo) {
        console.error("[ErrorBoundary]", error, info.componentStack);
    }

    render() {
        if (this.state.hasError) {
            if (this.props.fallback) {
                return this.props.fallback;
            }
            return (
                <div className="flex min-h-[40vh] items-center justify-center p-8">
                    <div className="max-w-md rounded-xl border border-red-400/30 bg-red-400/10 p-6 text-center">
                        <div className="mb-3 text-3xl" aria-hidden="true">⚠</div>
                        <h2 className="mb-2 text-lg font-semibold text-red-100">Something went wrong</h2>
                        <p className="mb-4 text-sm text-red-100/70">
                            {this.state.error?.message || "An unexpected error occurred."}
                        </p>
                        <button
                            type="button"
                            onClick={() => this.setState({ hasError: false, error: null })}
                            className="rounded-md border border-red-400/30 bg-red-500/20 px-4 py-2 text-sm text-red-100 hover:bg-red-500/30"
                        >
                            Try again
                        </button>
                    </div>
                </div>
            );
        }
        return this.props.children;
    }
}
