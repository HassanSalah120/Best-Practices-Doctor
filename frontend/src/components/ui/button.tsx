/* eslint-disable react-refresh/only-export-components */
import * as React from "react"
import { Slot } from "@radix-ui/react-slot"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

const buttonVariants = cva(
    "inline-flex items-center justify-center whitespace-nowrap rounded-xl text-sm font-medium transition-all duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:pointer-events-none disabled:opacity-50",
    {
        variants: {
            variant: {
                default:
                    "bg-primary text-primary-foreground shadow-[0_10px_30px_rgba(34,211,238,0.2)] hover:bg-primary/90",
                destructive:
                    "bg-destructive text-destructive-foreground shadow-sm hover:bg-destructive/90",
                outline:
                    "border border-white/10 bg-white/[0.045] text-white shadow-sm hover:border-white/20 hover:bg-white/[0.08]",
                secondary:
                    "bg-secondary text-secondary-foreground shadow-sm hover:bg-secondary/85",
                ghost: "text-white/70 hover:bg-white/[0.06] hover:text-white",
                link: "text-primary underline-offset-4 hover:underline",
                premium: "bg-[linear-gradient(135deg,rgba(34,211,238,1),rgba(59,130,246,0.96),rgba(45,212,191,0.96))] text-slate-950 shadow-[0_18px_40px_rgba(34,211,238,0.22)] hover:shadow-[0_22px_48px_rgba(34,211,238,0.28)] hover:brightness-105",
            },
            size: {
                default: "h-9 px-4 py-2",
                sm: "h-8 rounded-md px-3 text-xs",
                lg: "h-10 rounded-md px-8",
                icon: "h-9 w-9",
                xl: "h-12 px-10 text-base"
            },
        },
        defaultVariants: {
            variant: "default",
            size: "default",
        },
    }
)

export interface ButtonProps
    extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
    asChild?: boolean
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
    ({ className, variant, size, asChild = false, ...props }, ref) => {
        const Comp = asChild ? Slot : "button"
        return (
            <Comp
                className={cn(buttonVariants({ variant, size, className }))}
                ref={ref}
                {...props}
            />
        )
    }
)
Button.displayName = "Button"

export { Button, buttonVariants }
