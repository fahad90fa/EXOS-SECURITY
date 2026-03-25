import React, { ButtonHTMLAttributes } from 'react'

type Props = ButtonHTMLAttributes<HTMLButtonElement> & {
  tone?: 'primary' | 'secondary' | 'ghost'
}

export function Button({ tone = 'primary', className = '', ...props }: Props) {
  return <button className={`btn btn-${tone} ${className}`.trim()} {...props} />
}
