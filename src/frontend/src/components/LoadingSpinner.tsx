import clsx from 'clsx'

const sizes = {
  xs: 'h-3 w-3',
  sm: 'h-4 w-4', 
  md: 'h-6 w-6',
  lg: 'h-8 w-8',
  xl: 'h-12 w-12'
}

export default function LoadingSpinner({ size = 'md', className = '' }) {
  return (
    <div className={clsx('flex items-center justify-center', className)}>
      <div
        className={clsx(
          'animate-spin rounded-full border-2 border-gray-300 border-t-primary-600',
          sizes[size]
        )}
      />
    </div>
  )
}